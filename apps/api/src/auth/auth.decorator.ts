import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'isPublic';

export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

export const ACCEPTS_APP_AUDIENCE_KEY = 'acceptsAppAudience';

/**
 * The route also accepts an app audience token, with a matching
 * X-Eve-Audience header and only for the token's own project. Every other
 * route refuses those tokens.
 */
export const AcceptsAppAudience = () => SetMetadata(ACCEPTS_APP_AUDIENCE_KEY, true);
