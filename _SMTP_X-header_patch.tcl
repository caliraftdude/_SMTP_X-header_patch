# _SMTP_X-header_patch
# This iRule searches for a 354 message from the SMTP server, indicating it has seen a data command from the client and
# is expecting the client to send data.  It will then set a flag and then on the next client data message insert an X-header
# with the client IP address.  It then clears the flag and allows the conversation to continue.
#
# iRule is provided AS-IS with no support, guarantees, or assurances of any kind
# d.holland
# 2020.09.24

when RULE_INIT {
  # Initialize static items for the iRule
    
	# 1, 2, 4, or 8 or any sum of these for different log levels
	# 1 = Info
	# 2 = Warning
	# 4 = Error
	# 8 = Critical
	set static::debug 7

    call logger 1 "RULE_INIT" " _SMTP_X-header_patch iRule initialized"
}

when CLIENT_ACCEPTED {
    # Client has connected, collect IP address and build the X-header
    set clientAddr [IP::client_addr]
    set xheader "X-ClientIPAddress: $clientAddr"
    set f_data 0
    
    call logger 1 "CLIENT_ACCEPTED" "Client address: $clientAddr"
    TCP::collect
}

when SERVER_CONNECTED {
    # Begin collecting TCP payloads
    call logger 1 "SERVER_CONNECTED" "Starting to collect data on server side"
    TCP::collect
}

when SERVER_DATA {
    # Search for a 354 response from the server, indicating that the next client message should be data
    # Enable the STREAM_MATCHED event so we can process this
    call logger 1 "SERVER_DATA" "Collecting and searching data in server stream"
    STREAM::expression {@354 [Ee]nd data@@}
    STREAM::enable

    # Release the payload and continue collecting
    TCP::release
    TCP::collect
}

when CLIENT_DATA {
    call logger 1 "CLIENT_DATA" "Collecting and searching data in client stream.  f_data: ${f_data}"

    if { $f_data == 1 } {
        # If the f_data flag is set, then we expect when *this* event fires, its the client sending data.
        # Patch in our header here since doing it within the envelope headers causes errors.
        call logger 1 "CLIENT_DATA" "Patching in X-ClientIPAddress to the client data stream"

        # Patch in established header into existing TCP payload        
        set client_data [TCP::payload]
        #set payload "$xheader\r\n$client_data"
        
        # Goofy API.. if size is zero, command will INSERT and resize buffer to the new payload size
        TCP::payload replace 0 0 "$xheader\r\n"
        
        # Clear the f_data flag as we don't want to patch anymore data packets
        set f_data 0
    }
    
    # Release the payload and continue collecting
    TCP::release
    TCP::collect
}

when STREAM_MATCHED {
    call logger 1 "STREAM_MATCHED" "Found a match, processing..."
    set matched [STREAM::match]
    
    if { $matched contains "354" } {
        # Server has accepted DATA command and responded with a 354 - set data flag
        set f_data 1
        call logger 1 "STREAM_MATCHED" "f_data flag set to 1"

        # Fix the stream expression 
        STREAM::replace "$matched"
    }

    event STREAM_MATCHED disable
}

# proc logger
# params:
#    level:   Logging level for the message.  1, 2, 4, or 8 or any sum of these for different log levels
#    event:   Event that the message occurs in
#    message: The message to log
#
# todo:  Add HSL support
proc logger {level event message} {
	if {$static::debug & $level} {	
		log local0. "($event)::   $message"
	}
}
