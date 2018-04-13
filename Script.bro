
@load base/frameworks/notice
@load base/protocols/http

module HTTP;

export {
      # Append the value SQLILOG to the Log::ID enumerable.
      redef enum Log::ID += { SQLILOG };

      redef enum Tags += {
		    ## Indicator of a URI based SQL injection attack.
		      SQLI
	      };

    # Define a new type called .
    type SqliInfo: record {
        attacker:         addr &log;
        victim:           addr &log;
        URI:              string &log;
        low_confidence:   bool &log;
        high_confidence:  bool &log;
        };

        const strict_sqli_match = /^\/dvwa\/[^?]*\?(.*&)?id=[^&]*[^0-9&][^&]*(&.*)?$/ &redef;

        const union_sqli_match = /.*UNION.*/ &redef;

    }

event bro_init()
        {
          # Create the logging stream.
          Log::create_stream(HTTP::SQLILOG, [$columns=SqliInfo, $path="SQLI"]);
        }

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=3
	{
	if ( strict_sqli_match in unescaped_URI )
		{
		  add c$http$tags[SQLI];
      local u : bool = union_sqli_match in unescaped_URI;

      Log::write( HTTP::SQLILOG, [$attacker=c$id$orig_h,
                                  $victim=c$id$resp_h,
                                  $URI=original_URI,
                                  $low_confidence=T,
                                  $high_confidence=T]);

      NOTICE([$note=SQLI,
              $msg = "Attempted SQL Injection",
              $conn = c]);

		}
	}
