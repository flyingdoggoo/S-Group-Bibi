-- AlterTable
ALTER TABLE "public"."User" ADD COLUMN     "passwordResetTokenExpires" TIMESTAMP(3),
ADD COLUMN     "passwordResetTokenHash" TEXT;
