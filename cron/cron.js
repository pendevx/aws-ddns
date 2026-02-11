import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";
import { createHmac } from "crypto";

if (!process.env.PARAMETER_NAME) throw new Error("PARAMETER_NAME is not set");
if (!process.env.LAMBDA_ENDPOINT) throw new Error("LAMBDA_ENDPOINT is not set");

const PARAM_NAME = process.env.PARAMETER_NAME;
const parametersClient = new SSMClient();

const getSecretCommand = new GetParameterCommand({
    Name: PARAM_NAME,
});
const secretResponse = await parametersClient.send(getSecretCommand);
const secretValue = secretResponse.Parameter.Value;

const timestamp = Date.now().toString();
const hmacSignature = createHmac("sha256", secretValue)
    .update(timestamp)
    .digest("hex");

const res = await fetch(process.env.LAMBDA_ENDPOINT, {
    method: "POST",
    headers: {
        "X-Signature": hmacSignature,
        "X-Timestamp": timestamp,
    },
});

if (res.ok) console.log(`[${new Date().toISOString()}]: Execution successful.`);
else console.error(`[${new Date().toISOString()}]: something went wrong`);
