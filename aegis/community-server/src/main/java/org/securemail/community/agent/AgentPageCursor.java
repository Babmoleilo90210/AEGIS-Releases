package org.securemail.community.agent;

import org.securemail.community.core.CommunityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;

/** Short-lived pagination position; it never grants permission to read a list. */
final class AgentPageCursor implements AutoCloseable {
    record Position(String id, long created) { }
    private final byte[] key = new byte[32];
    AgentPageCursor() { new SecureRandom().nextBytes(key); }

    String encode(String actor, String action, long epoch, Position position, long now) throws Exception {
        byte[] body = AgentJson.bytes(Map.of("actor", actor, "action", action, "epoch", epoch,
                "id", position.id, "created", position.created, "expires", now + 900000));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(body) + "." +
                Base64.getUrlEncoder().withoutPadding().encodeToString(sign(body));
    }

    Position decode(String token, String actor, String action, long epoch, long now) throws Exception {
        try {
            if (token.length() > 2048) throw CommunityException.invalid();
            String[] parts = token.split("\\.", -1);
            if (parts.length != 2) throw CommunityException.invalid();
            byte[] body = Base64.getUrlDecoder().decode(parts[0]);
            byte[] signature = Base64.getUrlDecoder().decode(parts[1]);
            if (signature.length != 32 || !MessageDigest.isEqual(signature, sign(body))) throw CommunityException.invalid();
            Map<String,Object> data = AgentJson.object(body, 1024);
            if (!data.keySet().equals(Set.of("actor", "action", "epoch", "id", "created", "expires")) ||
                    !actor.equals(AgentJson.text(data, "actor", 128)) ||
                    !action.equals(AgentJson.text(data, "action", 80)) ||
                    epoch != AgentJson.number(data, "epoch", 0, Long.MAX_VALUE)) throw CommunityException.invalid();
            long expires = AgentJson.number(data, "expires", 0, Long.MAX_VALUE);
            if (expires < now || expires > now + 900000) throw CommunityException.invalid();
            return new Position(AgentJson.text(data, "id", 160), AgentJson.number(data, "created", 0, Long.MAX_VALUE));
        } catch (IllegalArgumentException | java.io.IOException invalid) {
            throw CommunityException.invalid();
        }
    }

    private byte[] sign(byte[] body) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(body);
    }
    @Override public void close() { Arrays.fill(key, (byte) 0); }
}
