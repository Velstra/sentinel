import {summary} from './harness.mjs';
import {refusalTests} from './refusal.mjs';
await refusalTests();
process.exitCode=summary()?1:0;
