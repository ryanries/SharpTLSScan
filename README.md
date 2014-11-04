SharpTLSScan
============

This application scans a server to see what versions of SSL and TLS it supports, and which cipher suites.

It is very similar to a program named sslscan (http://sourceforge.net/projects/sslscan/) and sslscan-win (http://code.google.com/p/sslscan-win/) but those programs had not been updated in 5 years, and thus did not support TLS 1.1 or 1.2, which is why I wrote this tool.

You can download the source code here, or you can grab the executable from my blog https://www.myotherpcisacloud.com/post/2014/08/22/sharptlsscan-v12.aspx


Updated to v1.3. Changed all SSLv3 to YELLOW because Poodle. Removed the
"Working..." text because it messes with stdout and that makes it more
difficult for other programs to parse the output of this program if you
want to use this program in an automated fashion. Added a NoSchannel
argument, which bypasses the certificate and SChannel stuff and gets
straight to the cipher scanning.


![Screenshot](./screen1.PNG)

![Screenshot](./screen2.PNG)
