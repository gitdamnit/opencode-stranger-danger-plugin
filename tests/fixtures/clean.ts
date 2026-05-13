// Clean fixture — contains zero secrets, must produce 0 findings

export const cleanContent = `
import { createServer } from "node:http";

const PORT = 3000;
const HOST = "localhost";

const server = createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("Hello, World!\n");
});

server.listen(PORT, HOST, () => {
    console.log(\`Server running at http://\${HOST}:\${PORT}/\`);
});

export default server;
`;
