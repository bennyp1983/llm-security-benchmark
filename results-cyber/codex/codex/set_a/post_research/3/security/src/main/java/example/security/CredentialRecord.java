package example.security;

record CredentialRecord(String algorithm, int iterations, byte[] salt, byte[] passwordHash, boolean enabled) {}
