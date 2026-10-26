import { build } from "esbuild";
import { mkdir, readFile, writeFile } from "node:fs/promises";
const notices = await Promise.all(
  ["react", "react-dom", "scheduler", "diff"].map(async (name) => {
    const license = await readFile(`node_modules/${name}/LICENSE`, "utf8");
    if (license.includes("*/")) throw Error("Unsafe license comment delimiter");
    return `${name}\n${license.trim()}`;
  }),
);
const result = await build({
  entryPoints: ["src/index.tsx"],
  bundle: true,
  write: false,
  minify: true,
  format: "iife",
  target: ["es2022"],
  charset: "ascii",
  legalComments: "inline",
  banner: { js: "/*! Third-party notices\n\n" + notices.join("\n\n") + "\n*/" },
  define: { "process.env.NODE_ENV": '"production"' },
  outfile: "dist/management.js",
});
await mkdir("dist", { recursive: true });
for (const file of result.outputFiles) {
  if (process.argv.includes("--check")) {
    if (!Buffer.from(file.contents).equals(await readFile(file.path)))
      throw Error("Embedded assets are stale. Run npm run build in ui/.");
  } else await writeFile(file.path, file.contents);
}
