-- AlterTable
ALTER TABLE "public"."User" ADD COLUMN     "lastLoginAt" TIMESTAMP(3),
ADD COLUMN     "refreshTokenHash" TEXT;
