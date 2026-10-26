## Important Notices

It is available from Jennifer Server version 5.4.0


## Getting started

Execute the following in the Jennifer management screen.

 1. Extension & Notice > Adapter and Plugin
 2. Click the Add button.
 3. Select the 'PAGE' type.
 4. Enter the 'ldap_adapter' ID.
 5. Enter the adapter path directly or upload the file.
 6. Enter the class 'com.aries.ldaplogin.LoginAdapter'.


## How to use Options

Adapter options are shown in the table below.

| Key           | Example |
| ------------- |:-------------:|
| serverUrl       | LDAP://127.0.0.0 |
| baseRdn   | cn=admin,dc=admin,dc=com |
| baseOu | JenniferSoft |
| adminId | CN=Users |
| adminPwd | 1234 |
| groupPrefix | JS_,jennifer_ |
| fixedGroup | |
| useSsl | false |


## Using LDAPS (SSL)

Supported from adapter version 1.2.0. Use 1.2.1 or later, which logs the root cause of connection failures.

 1. Set `serverUrl` to the LDAPS address, for example `ldaps://ad.example.com:636`.
 2. Set `useSsl` to `true`.
 3. Make the view server's JVM trust the LDAP server certificate. Use either of the following.
    - Import the CA certificate into the `cacerts` of the JRE that runs the view server.
      `keytool -importcert -trustcacerts -alias ldaps-ca -file ldaps-ca.cer -keystore <JAVA_HOME>/jre/lib/security/cacerts`
    - Or create a separate truststore and add JVM options where the view server is actually started (start script or Windows service settings).
      `-Djavax.net.ssl.trustStore=<path>/ldaps-trust.jks -Djavax.net.ssl.trustStorePassword=<password>`
 4. The host name in `serverUrl` must match the CN or SAN of the LDAP server certificate.
 5. Restart the view server.

Notes

 - `ssl_truststore_path` in `server_view.conf` and the `SslContextFactory ... trustStore=null` startup log are for the view server's own HTTPS (Jetty). They are not related to LDAPS.
 - If an LDAPS connection fails, version 1.2.1 or later also logs `SSL handshake check failed: ...` with the actual cause. For example, `PKIX path building failed` means the certificate is not trusted, and `No subject alternative names` or `No name matching` means the host name does not match the certificate.
 - To see the full SSL handshake, add `-Djavax.net.debug=ssl:handshake` temporarily.
