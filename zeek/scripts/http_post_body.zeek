@load base/protocols/http

# Extracts HTTP POST bodies from HTTP requests.

module HttpPostBody;

export {
	## The length of POST bodies to extract.
	const http_post_body_length = 10000 &redef;
}

redef record HTTP::Info += {
	post_body: string &log &optional;
};

event log_post_bodies(f: fa_file, data: string)
	{
	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];
		if ( ! c$http?$post_body )
			c$http$post_body = "";

		# If we are already above the captured size here, just return.
		if ( |c$http$post_body| > http_post_body_length )
			return;

		c$http$post_body = c$http$post_body + data;
		if ( |c$http$post_body| > http_post_body_length )
			{
			c$http$post_body = c$http$post_body[0:http_post_body_length] + "...";
			}
		}
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	if ( is_orig && c?$http && c$http?$method && c$http$method == "POST" )
		{
		Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=log_post_bodies]);
		}
	}
