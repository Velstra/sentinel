import {emptyPolicyTests} from './empty-policy.mjs';
import {summary} from './harness.mjs';
await emptyPolicyTests();
process.exitCode=summary()?1:0;
