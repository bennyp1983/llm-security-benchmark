package portal.security;

/** Injectable time source so lockout and session expiry can be tested without sleeping. */
@FunctionalInterface
public interface Clock {

    long currentTimeMillis();

    Clock SYSTEM = System::currentTimeMillis;

    /** Manual clock for tests and simulations; time only moves when told to. */
    final class Fake implements Clock {

        private long millis;

        public Fake() {
            this(1_700_000_000_000L);
        }

        public Fake(long startMillis) {
            this.millis = startMillis;
        }

        @Override
        public long currentTimeMillis() {
            return millis;
        }

        public long now() {
            return millis;
        }

        public void advance(long deltaMillis) {
            if (deltaMillis < 0) {
                throw new IllegalArgumentException("time cannot go backwards");
            }
            millis += deltaMillis;
        }

        public void setTo(long millis) {
            if (millis < this.millis) {
                throw new IllegalArgumentException("time cannot go backwards");
            }
            this.millis = millis;
        }
    }
}

