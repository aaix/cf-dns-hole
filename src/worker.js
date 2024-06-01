
export default {
  async fetch(request, env, ctx) {

    let url = new URL(request.url);

    url.host = "cloudflare-dns.com"

    if (url.pathname != "/dns-query") {
      return respond("unsupported path", 400)
    }


    const body = await request.arrayBuffer()


    let host;
    switch (request.headers.get("Accept")) {

      // json query
      case "application/dns-json":
        host = url.searchParams.get("name");
        console.log(`JSON REQUEST for: ${host}`);
        break;

      // binary dns query
      case "application/dns-message":


        const dnsMessage = new Uint8Array(body)

        // Parse the DNS request to extract the requested host
        host = parseDnsRequest(dnsMessage)


        console.log(`BIN REQUEST FOR : ${host}`)

        break;
      default:
        return respond("Invalid Accept Header", 400)
    }

    const query = url.searchParams.get("name");

    


    return await fetch(
      new Request(
        url,
        {
          body:request.method=="POST" ? body : null,
          method:request.method,
          headers:request.headers,
          redirect:request.redirect,
        }
      )
    );
  },
};


function respond(text, status) {
  return new Response(
    text,
    {
      status:status
    }
  )
}

// THANKS CHATGPT
function parseDnsRequest(dnsMessage) {
  // DNS header is 12 bytes; we start reading questions after this
  let offset = 12

  // Question section: Name (variable length), Type (2 bytes), Class (2 bytes)
  const nameParts = []

  while (true) {
    const length = dnsMessage[offset++]
    if (length === 0) break // End of the Name section
    const part = dnsMessage.slice(offset, offset + length)
    nameParts.push(String.fromCharCode(...part))
    offset += length
  }

  // Join the name parts with dots
  const host = nameParts.join('.')
  
  return host
}