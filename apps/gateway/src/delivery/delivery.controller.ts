import {
  Body,
  Controller,
  Headers,
  HttpCode,
  HttpStatus,
  Post,
} from '@nestjs/common';
import { GatewayProviderRegistry } from '../providers/provider-registry.js';
import { formatAgentReply } from '../providers/slack/slack-format.js';
import { createJsonLogger } from '@eve/shared';
import { assertDeliverCaller } from '../internal-auth.js';

const logger = createJsonLogger('gateway');

interface DeliveryRequest {
  provider: string;
  account_id: string;
  channel_id: string;
  thread_id?: string;
  text: string;
}

@Controller('internal')
export class DeliveryController {
  constructor(private readonly registry: GatewayProviderRegistry) {}

  @Post('deliver')
  @HttpCode(HttpStatus.OK)
  async handleDelivery(
    @Headers() headers: Record<string, string | string[] | undefined>,
    @Body() body: DeliveryRequest,
  ) {
    // Only the services that deliver: the deliver key, or the legacy key.
    assertDeliverCaller(headers);

    if (!body.provider || !body.account_id || !body.channel_id || !body.text) {
      return { delivered: false, reason: 'missing_fields' };
    }

    const provider = this.registry.getInstance(body.provider, body.account_id);
    if (!provider) {
      logger.warn({
        event: 'delivery.provider_missing',
        provider: body.provider,
        accountId: body.account_id,
        msg: `No active provider instance for ${body.provider}:${body.account_id} — message already persisted, skipping push`,
      });
      return { delivered: false, reason: 'no_provider_instance' };
    }

    // Format with mrkdwn conversion + chunked Block Kit sections for Slack.
    // Non-Slack providers ignore blocks and use plain text.
    const formatted = formatAgentReply(body.text);

    await provider.sendMessage(
      {
        provider: body.provider,
        accountId: body.account_id,
        channel: body.channel_id,
        threadId: body.thread_id,
      },
      formatted,
    );

    return { delivered: true };
  }
}
