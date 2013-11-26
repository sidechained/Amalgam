import httplib
import requests
import sys

def main():
    if len(sys.argv) != 2:
        print "Usage: %s " % sys.argv[0]
        return 1

    headers = { 'Accept-Encoding' : 'identity' }
    sess = requests.sessions.Session()
    sess.headers.update(headers)
    sess.verify = False
    sess.prefetch = False
    sess.hooks.update(response=response_hook)
    resp = sess.get(sys.argv[1])
    cb = lambda x: sys.stdout.write("Read: %s\n" % x)
    for chunk in resp.iter_chunks():
        cb(chunk)

def response_hook(response, *args, **kwargs):
    response.iter_chunks = lambda amt=None: iter_chunks(response.raw._fp, amt=amt)
    return response

def iter_chunks(response, amt=None):
    """
    A copy-paste version of httplib.HTTPConnection._read_chunked() that
    yields chunks served by the server.
    """
    if response.chunked:
        while True:
            line = response.fp.readline().strip()
            arr = line.split(';', 1)
            try:
                chunk_size = int(arr[0], 16)
            except ValueError:
                response.close()
                raise httplib.IncompleteRead(chunk_size)
            if chunk_size == 0:
                break
            value = response._safe_read(chunk_size)
            yield value
            # we read the whole chunk, get another
            response._safe_read(2)      # toss the CRLF at the end of the chunk

        # read and discard trailer up to the CRLF terminator
        ### note: we shouldn't have any trailers!
        while True:
            line = response.fp.readline()
            if not line:
                # a vanishingly small number of sites EOF without
                # sending the trailer
                break
            if line == '\r\n':
                break

        # we read everything; close the "file"
        response.close()
    else:
        # Non-chunked response. If amt is None, then just drop back to
        # response.read()
        if amt is None:
            yield response.read()
        else:
            # Yield chunks as read from the HTTP connection
            while True:
                ret = response.read(amt)
                if not ret:
                    break
                yield ret

if __name__ == '__main__':
    sys.exit(main())
