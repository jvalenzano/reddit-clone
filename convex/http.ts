import { httpRouter } from "convex/server";
import { httpAction } from "./_generated/server";
import { internal } from "./_generated/api";
import type { WebhookEvent } from "@clerk/backend";
import { Webhook } from "svix";

const http = httpRouter();

http.route({
  path: "/clerk-users-webhook",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    console.log("Received webhook request");

    try {
      // Validate the webhook request
      const event = await validateRequest(request);

      if (!event) {
        console.error("Failed to validate webhook request");
        return new Response("Invalid webhook request", { status: 400 });
      }

      console.log(`Processing webhook event: ${event.type} for user ID: ${event.data.id}`);

      // Process the webhook based on event type
      switch (event.type) {
        case "user.created":
          console.log("User created event:", JSON.stringify({
            id: event.data.id,
            username: event.data.username,
            email: event.data.email_addresses?.[0]?.email_address
          }));
          await ctx.runMutation(internal.users.upsertFromClerk, {
            data: event.data,
          });
          console.log("Successfully processed user.created event");
          break;

        case "user.updated":
          console.log("User updated event:", JSON.stringify({
            id: event.data.id,
            username: event.data.username
          }));
          await ctx.runMutation(internal.users.upsertFromClerk, {
            data: event.data,
          });
          console.log("Successfully processed user.updated event");
          break;

        case "user.deleted": {
          const clerkUserId = event.data.id!;
          console.log(`User deleted event for ID: ${clerkUserId}`);
          await ctx.runMutation(internal.users.deleteFromClerk, { clerkUserId });
          console.log("Successfully processed user.deleted event");
          break;
        }

        default:
          console.log(`Unhandled Clerk webhook event type: ${event.type}`);
      }

      return new Response("Webhook processed successfully", { status: 200 });
    } catch (error) {
      // Log the error with detailed information
      console.error("Error processing webhook:", error);

      // Return a more informative error response
      return new Response(
        JSON.stringify({
          error: "Error processing webhook",
          message: error instanceof Error ? error.message : "Unknown error"
        }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
  }),
});

async function validateRequest(req: Request): Promise<WebhookEvent | null> {
  try {
    // Check if webhook secret is configured
    if (!process.env.CLERK_WEBHOOK_SECRET) {
      console.error("CLERK_WEBHOOK_SECRET environment variable is not set");
      return null;
    }

    console.log("Extracting webhook payload and headers");

    // Get the request body
    const payloadString = await req.text();

    // Get the Svix headers for verification
    const svixId = req.headers.get("svix-id");
    const svixTimestamp = req.headers.get("svix-timestamp");
    const svixSignature = req.headers.get("svix-signature");

    // Log header information for debugging
    console.log("Webhook headers:", JSON.stringify({
      "svix-id": svixId ? "present" : "missing",
      "svix-timestamp": svixTimestamp ? "present" : "missing",
      "svix-signature": svixSignature ? "present" : "missing"
    }));

    // Verify all required headers are present
    if (!svixId || !svixTimestamp || !svixSignature) {
      console.error("Missing required Svix headers");
      return null;
    }

    const svixHeaders = {
      "svix-id": svixId,
      "svix-timestamp": svixTimestamp,
      "svix-signature": svixSignature,
    };

    // Attempt to verify the webhook
    console.log("Verifying webhook signature");
    const wh = new Webhook(process.env.CLERK_WEBHOOK_SECRET);
    const event = wh.verify(payloadString, svixHeaders) as unknown as WebhookEvent;

    console.log("Webhook verification successful");
    return event;
  } catch (error) {
    console.error("Error validating webhook:", error);
    return null;
  }
}

export default http;
