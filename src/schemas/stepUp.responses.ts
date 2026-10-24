/*
 * Copyright © 2026 Fells Code, LLC
 * Licensed under the Apache License, Version 2.0
 * See LICENSE file in the project root for full license information
 */

import { StepUpStatusSchema } from '@seamless-auth/types';

import { ErrorSchema } from './generic.responses.js';

export { StepUpStatusSchema, StepUpSuccessSchema } from '@seamless-auth/types';

/**
 * The 403 of a route behind `requireStepUp()`. A missing step-up answers
 * `error: 'step_up_required'` with the session's step-up status, while a missing admin
 * role answers the same status with `{ error }` alone, so the status fields are optional.
 */
export const StepUpRequiredErrorSchema = ErrorSchema.extend(StepUpStatusSchema.partial().shape);
