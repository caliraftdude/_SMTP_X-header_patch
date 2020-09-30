## _SMTP_X-header_patch
This iRule is used to insert an X-Header into an SMTP email stream


Additional resources to add STARTTLS support:
 * irulsology-smtp-start-tls[link](https://devcentral.f5.com/s/articles/iruleologyndashsmtp-start-tls)
 * SSL_enable [link](https://clouddocs.f5.com/api/irules/SSL__enable.html)
 * starttls server smtp with cleartext and starttls client support [link](https://devcentral.f5.com/s/articles/starttls-server-smtp-with-cleartext-and-starttls-client-support-1209)
 * Postfix TLS readme [link](http://www.postfix.org/TLS_README.html)
 * How to make an echo server with bash [link](https://stackoverflow.com/questions/8375860/how-to-make-an-echo-server-with-bash)
 * SMTP starttls [link](https://devcentral.f5.com/s/articles/smtpstarttls)

# Sample Code
```tcl
    when CLIENT_ACCEPTED {
        set ehlo 0
        SSL::disable
    }
    when SERVER_CONNECTED {
        TCP::collect
    }
    when CLIENT_DATA {
        set lcpayload [string tolower [TCP::payload]]
        if { $lcpayload starts_with "ehlo" } {
            set ehlo 1
            serverside { TCP::collect }
            TCP::release
            TCP::collect
        } elseif { $lcpayload starts_with "starttls" } {
            TCP::respond "220 Ready to start TLS\r\n"
            TCP::payload replace 0 [TCP::payload length] ""
            TCP::release
            SSL::enable
        } else {
            TCP::release
        }
    }
    when SERVER_DATA {
        if { $ehlo == 1 and not([string tolower [TCP::payload]] contains "starttls") } {
            TCP::payload replace 0 0 "250-STARTTLS\r\n"
        }
        TCP::release
        clientside { TCP::collect }
    }
```
