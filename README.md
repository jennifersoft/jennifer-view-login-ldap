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
