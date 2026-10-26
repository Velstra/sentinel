import { createRoot } from "react-dom/client";
import { flushSync } from "react-dom";
import { Management } from "./controller";
import type { Host } from "./model";
import { Dashboard, Flows, ConfigEditor, Confirmation } from "./components";
import "./shell.css";
import "./style.css";

declare global {
  interface Window {
    SentinelReact: { mount(host: Host): Management };
  }
}
window.SentinelReact = {
  mount(host) {
    const manager = new Management(host);
    // Separate roots integrate with the established appliance navigation. React
    // owns each entire migrated workflow; the shell never rewrites these children.
    for (const [id, Component] of [
      ["react-dashboard", Dashboard],
      ["react-flows", Flows],
      ["react-config", ConfigEditor],
      ["react-confirmation", Confirmation],
    ] as const) {
      const root = document.getElementById(id);
      if (!root) throw Error("Missing React mount " + id);
      flushSync(() => createRoot(root).render(<Component manager={manager} />));
    }
    return manager;
  },
};
