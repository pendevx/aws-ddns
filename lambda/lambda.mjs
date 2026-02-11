import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";
import {
    Route53Client,
    ChangeResourceRecordSetsCommand,
} from "@aws-sdk/client-route-53";
import { createHmac } from "crypto";

const HOSTED_ZONE_ID = process.env.HOSTED_ZONE_ID;
const RECORD_NAME = process.env.RECORD_NAME;
const RECORD_TTL = parseInt(process.env.RECORD_TTL || "300");
const route53Client = new Route53Client();

const PARAMETER_NAME = process.env.PARAMETER_NAME;
const ssmClient = new SSMClient();

const validateSignature = async (event) => {
    const signatureHeader = event.headers?.["X-Signature"];

    const timestamp = event.headers?.["X-Timestamp"] || Date.now().toString();

    const getParameterCommand = new GetParameterCommand({
        Name: PARAMETER_NAME,
    });
    const parameterResponse = await ssmClient.send(getParameterCommand);
    const secretValue = parameterResponse.Parameter.Value;

    const expectedSignature = createHmac("sha256", secretValue)
        .update(timestamp)
        .digest("hex");

    if (signatureHeader !== expectedSignature) {
        throw new Error("Invalid signature");
    }

    const timeDiff = Date.now() - parseInt(timestamp);
    if (Math.abs(timeDiff) > 300000) {
        throw new Error("Timestamp expired");
    }
};

export const handler = async (event) => {
    try {
        await validateSignature(event);

        let clientIp = event.requestContext.identity.sourceIp;

        const changeCommand = new ChangeResourceRecordSetsCommand({
            HostedZoneId: HOSTED_ZONE_ID,
            ChangeBatch: {
                Changes: [
                    {
                        Action: "UPSERT",
                        ResourceRecordSet: {
                            Name: RECORD_NAME,
                            Type: "A",
                            TTL: RECORD_TTL,
                            ResourceRecords: [{ Value: clientIp }],
                        },
                    },
                ],
            },
        });

        const result = await route53Client.send(changeCommand);

        return {
            statusCode: 200,
            body: JSON.stringify({
                success: true,
                ip: clientIp,
                record: RECORD_NAME,
                changeId: result.ChangeInfo.Id,
            }),
        };
    } catch (error) {
        console.error("Error:", error);

        const statusCode = error.message === "Invalid signature" ? 401 : 500;

        return {
            statusCode: statusCode,
            body: JSON.stringify({
                success: false,
                error: error.message,
            }),
        };
    }
};
