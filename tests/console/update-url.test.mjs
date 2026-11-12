import {summary} from './harness.mjs';
import {updateUrlTests} from './update-url.mjs';
await updateUrlTests();
process.exitCode=summary()?1:0;
