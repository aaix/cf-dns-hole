import { Buffer} from "node:buffer"
const FILTER = require("./filter.js")

globalThis.Buffer = Buffer;

const bf = require("@mcrowe/minibloom");


export default {
  async fetch(request, env, ctx) {


    let url = new URL(request.url);

    url.host = "cloudflare-dns.com"

    if (url.pathname != "/dns-query") {
      return respond("unsupported path", 400)
    }


    const body = await request.arrayBuffer()


    let host;
    let parsed;
    let type;
    let qclass;
    let isJson = null;
    switch (request.headers.get("Accept")) {

      // json query
      case "application/dns-json":
        isJson = true;
        host = url.searchParams.get("name");
        type = url.searchParams.get("type");

        console.log(`JSON REQUEST for: ${host} type ${type}`);
        break;

      // binary dns query
      case "application/dns-message":
        isJson = false;

        const dnsMessage = new Uint8Array(body)

        // Parse the DNS request to extract the requested host
        let qclass;
        try {
          parsed = parseDnsRequest(dnsMessage)
          host = parsed.host;
          type = parsed.question.slice(-4, -2);
          qclass = parsed.question.slice(-2);
        } catch {
          return respond("failed to parse dns body", 400)
        }


        console.log(`BIN REQUEST FOR : ${host} type ${type} class ${qclass}`);

        break;
      default:
        return respond("Invalid Accept Header", 400)
    }


    if (!host) {
      return respond("No query", 400)
    }



    // make the upstream request
    // concurrently as we do our blocklist check

    url.protocol = "https"

    const fetchPromise = fetch(
      new Request(
        url,
        {
          body:request.method=="POST" ? body : null,
          method:request.method,
          headers:request.headers,
          redirect:request.redirect,
        }
      )
    )


    const bloom = bf.fromBuffer(Buffer.from(FILTER.BLOOM, "base64"))

    if (bloom.test(host)) {
      console.log(`BLOCKED: ${host}`);
      return denyRequest(isJson, parsed);
    }


    return await fetchPromise;
  },
};


function respond(text, status) {
  console.log("responding", text, status)
  return new Response(
    text,
    {
      status:status
    }
  )
}


function denyRequest(isJson, body) {
  return isJson ? denyRequestJson() : denyRequestWireformat(body);
}

function parseByte(byte) {
  // display a-z and ascii characters
  if (byte >= 0x20 && byte <= 0x7e) {
    return String.fromCharCode(byte);
  }
  return byte.toString(16);
}


function denyRequestWireformat(body) {


  const response = new Uint8Array([
    ...body.id, // Transaction ID
    0x85, 0x83, // Flags: Standard query response, No such name (NXDOMAIN)
    0x00, 0x01, // Questions: 1
    0x00, 0x00, // Answer RRs: 0
    0x00, 0x00, // Authority RRs
    0x00, 0x00,  // Additional RRs: 0
    ...body.question,
  ]);

  // console.log("DENYING", Array.from(response).map(x=>parseByte(x)))

  return new Response(
    response, 
    {
      status: 200,
      headers: {
        "Content-Type": "application/dns-message"
      }
    }
  );
}


function denyRequestJson() {
  return new Response(
    JSON.stringify(
      {
        Status:2,
        TC:false,
        RD:true,
        RA:true,
        AD:false,
        CD:false,
        Question:[
          {
            name:"",
            type:1
          }
        ],
        Answer:[],
        Comment:"Blocked"
      }
    ),
    {
      status:200,
      headers:{
        "Content-Type":"application/dns-json"
      }
    }
  )
}




// THANKS CHATGPT
function parseDnsRequest(dnsMessage) {
  // DNS header is 12 bytes; we start reading questions after this
  let offset = 12;

  const nameParts = [];
  const originalOffset = offset; // Store the initial offset for later

  while (true) {
    const length = dnsMessage[offset++];

    if (length === undefined) {
      throw new Error("bad packet");
    }

    if (length === 0) break; // End of the Name section
    const part = dnsMessage.slice(offset, offset + length);
    nameParts.push(String.fromCharCode(...part));
    offset += length;
  }

  // Join the name parts with dots
  const host = nameParts.join('.');

  // Include QTYPE (2 bytes) and QCLASS (2 bytes)
  const questionEnd = offset + 4;
  const question = dnsMessage.slice(originalOffset, questionEnd);

  const id = dnsMessage.slice(0, 2);

  return { host, question, id };
}