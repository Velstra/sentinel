import {summary} from './harness.mjs';
import {workflowTests} from './workflow.mjs';
await workflowTests();
process.exitCode=summary()?1:0;
