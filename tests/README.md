smoke.py drives the server over stdio like a real MCP client. It needs a key with a ZERO
spend cap (so the start call is refused by the API) and two local audio files. It creates
real (never started) evaluations on the key's account and cancels them; delete the uploads
afterwards if you care about a tidy file list.
