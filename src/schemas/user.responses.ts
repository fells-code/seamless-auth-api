import z from 'zod';

export const DeleteUserResponseSchema = z.object({
  success: z.boolean(),
});
