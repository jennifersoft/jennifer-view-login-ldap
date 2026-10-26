package com.aries.ldaplogin

import com.aries.extension.util.LogUtil
import java.lang.NullPointerException
import java.net.InetSocketAddress
import java.net.URI
import java.util.*
import javax.naming.AuthenticationException
import javax.naming.CommunicationException
import javax.naming.Context
import javax.naming.NamingException
import javax.naming.directory.DirContext
import javax.naming.directory.SearchControls
import javax.naming.directory.SearchResult
import javax.naming.ldap.InitialLdapContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

object LdapConnector {
    // serverUrl에 포트가 없을 때 쓰는 LDAPS 기본 포트
    private const val DEFAULT_LDAPS_PORT = 636
    // SSL 진단 접속의 연결·읽기 제한 시간(ms)
    private const val SSL_CHECK_TIMEOUT_MS = 5000

    fun connect(usrId: String, usrPw: String,
                url: String="",  baseRdn: String="",
                ntUserId: String="", ntPasswd: String="",
                groupPrefix: List<String> = emptyList(), baseOu: String="",
                fixedGroup: String = "", useSsl: Boolean=false): String? {
        try {
            val env = Hashtable<String, String>()
            env[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
            env[Context.PROVIDER_URL] = url
            if (useSsl) env[Context.SECURITY_PROTOCOL] = "ssl"
            env[Context.SECURITY_AUTHENTICATION] = "simple"
            env[Context.SECURITY_PRINCIPAL] = ntUserId
            env[Context.SECURITY_CREDENTIALS] = ntPasswd

            val ctx = InitialLdapContext(env, null)
            LogUtil.info("Active Directory Connection: CONNECTED")

            val results = findAccountByAccountName(ctx, baseRdn, usrId)
            val user = results!!.nameInNamespace
            val usrEnv = Hashtable<String, String>()
            usrEnv[Context.INITIAL_CONTEXT_FACTORY] = "com.sun.jndi.ldap.LdapCtxFactory"
            usrEnv[Context.PROVIDER_URL] = url
            if (useSsl) usrEnv[Context.SECURITY_PROTOCOL] = "ssl"
            usrEnv[Context.SECURITY_AUTHENTICATION] = "simple"
            usrEnv[Context.SECURITY_PRINCIPAL] = user
            usrEnv[Context.SECURITY_CREDENTIALS] = usrPw
            InitialLdapContext(usrEnv, null)

            // fixedGroup 옵션을 사용하면, OU와 CN 체크를하지 않는다.
            if (fixedGroup != "")
                return fixedGroup

            return getJenniferUserGroup(results, groupPrefix, baseOu)
        } catch (e: AuthenticationException) {
            val msg = e.message!!
            when {
                msg.indexOf("data 525") > 0 -> LogUtil.warn("User not found (525)")
                msg.indexOf("data 773") > 0 -> LogUtil.warn("The user must reset the password (773)")
                msg.indexOf("data 52e") > 0 -> LogUtil.warn("ID and password do not match (52e)")
                msg.indexOf("data 533") > 0 -> LogUtil.warn("The ID you entered is inactive (533)")
                msg.indexOf("data 532") > 0 -> LogUtil.warn("Password has expired (532)")
                msg.indexOf("data 701") > 0 -> LogUtil.warn("The account has expired in AD (701)")
                else -> LogUtil.error(describeError(e))
            }
            return null
        } catch (e: NamingException) {
            LogUtil.error(describeError(e))
            // LDAPS 연결 실패는 JDK에 따라 원인이 "simple bind failed"로 가려지므로, 직접 핸드셰이크해서 원인을 남긴다.
            if (useSsl && e is CommunicationException) checkSslHandshake(url)
            return null
        } catch (e: NullPointerException) {
            LogUtil.error("User not found in namespace")
            return null
        }

        return null
    }

    @Throws(NamingException::class)
    fun findAccountByAccountName(ctx: DirContext, ldapSearchBase: String?, accountName: String): SearchResult? {
        val searchFilter = "(&(objectClass=user)(sAMAccountName=$accountName))"
        val searchControls = SearchControls()
        searchControls.searchScope = SearchControls.SUBTREE_SCOPE
        val results = ctx.search(ldapSearchBase, searchFilter, searchControls)
        var searchResult: SearchResult? = null
        if (results.hasMoreElements()) {
            searchResult = results.nextElement() as SearchResult

            //make sure there is not another item available, there should be only 1 match
            if (results.hasMoreElements()) {
                LogUtil.error("Matched multiple users for the accountName: $accountName")
                return null
            }
        }
        return searchResult
    }

    private fun getJenniferUserGroup(results: SearchResult, groupPrefix: List<String> = emptyList(), baseOu: String=""): String? {
        val attributes = results.attributes
        val memberOf = attributes["memberOf"]

        if (memberOf != null) {
            for (i in 0 until memberOf.size()) {
                val ouList = takeValues(memberOf[i].toString(), "OU")
                val cnList = takeValues(memberOf[i].toString(), "CN")

                // baseOu 옵션을 사용할 경우
                if (baseOu != "" && !ouList.contains(baseOu)) {
                    LogUtil.error("The set 'baseOu' does not contain any users")
                    return null
                }

                // groupPrefix 옵션을 사용할 경우
                if (groupPrefix.isNotEmpty()) {
                    groupPrefix.forEach { prefix ->
                        val cn = cnList.filter { it.startsWith(prefix) }
                        if (cn.isNotEmpty())
                            return cn[0]
                    }
                }
            }
        }

        LogUtil.error("The group of LDAP users does not belong to the JENNIFER user group")
        return null
    }

    /**
     * 예외 메시지에 최종 원인(root cause)을 붙인다.
     * LDAPS 실패는 "simple bind failed" 같은 메시지만 남고 실제 원인(인증서 신뢰 실패, 호스트명 불일치 등)은
     * cause 쪽에만 있어서, 원인을 함께 남겨야 진단할 수 있다.
     */
    private fun describeError(e: Throwable): String {
        var root: Throwable = e
        while (root.cause != null && root.cause !== root) {
            root = root.cause!!
        }
        return if (root === e) "${e.message}"
        else "${e.message} (cause: ${root.javaClass.name}: ${root.message})"
    }

    /**
     * serverUrl로 SSL 핸드셰이크만 따로 시도해 결과를 로그에 남긴다.
     * 인증서 신뢰 실패(PKIX path building failed), 호스트명 불일치, 포트 문제 등을 구분하기 위한 진단용이다.
     */
    private fun checkSslHandshake(url: String) {
        try {
            // PROVIDER_URL은 공백으로 여러 주소를 줄 수 있으므로 첫 번째 주소만 확인한다.
            val uri = URI(url.trim().split(" ")[0])
            val port = if (uri.port > 0) uri.port else DEFAULT_LDAPS_PORT
            val socket = SSLSocketFactory.getDefault().createSocket() as SSLSocket
            socket.use {
                it.connect(InetSocketAddress(uri.host, port), SSL_CHECK_TIMEOUT_MS)
                it.soTimeout = SSL_CHECK_TIMEOUT_MS
                // JNDI LDAPS와 같은 기준으로 인증서의 호스트명을 검증한다.
                val params = it.sslParameters
                params.endpointIdentificationAlgorithm = "LDAPS"
                it.sslParameters = params
                it.startHandshake()
            }
            LogUtil.info("SSL handshake check succeeded (${uri.host}:$port)")
        } catch (e: Exception) {
            LogUtil.error("SSL handshake check failed: ${describeError(e)}")
        }
    }

    private fun takeValues(args: String, key: String): Set<String> {
        val result = HashSet<String>()
        val tokens = args.split(",")
        for (token in tokens) {
            val keyAndValue = token.split("=")
            if (key == keyAndValue[0]) {
                result.add(keyAndValue[1])
            }
        }
        return result
    }
}
