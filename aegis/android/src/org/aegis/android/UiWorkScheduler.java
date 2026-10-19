package org.aegis.android;

import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;

/** Lifecycle fencing applies to optional data work, never to mandatory security cleanup. */
public final class UiWorkScheduler {
    private UiWorkScheduler() {}
    public static void execute(Executor executor, boolean security, long submitted,
                               LongSupplier epoch, BooleanSupplier closed, Runnable action) {
        execute(executor,security,submitted,epoch,closed,action,()->{});
    }
    public static void execute(Executor executor, boolean security, long submitted,
                               LongSupplier epoch, BooleanSupplier closed, Runnable action, Runnable discarded) {
        Objects.requireNonNull(executor);Objects.requireNonNull(epoch);
        Objects.requireNonNull(closed);Objects.requireNonNull(action);Objects.requireNonNull(discarded);
        var task=new OwnedTask(security,submitted,epoch,closed,action,discarded);
        try {executor.execute(task);} catch(RuntimeException rejected) {task.discard();throw rejected;}
    }
    /** Cleanup of an optional queued task removed by ExecutorService.shutdownNow(). */
    public static void discard(Runnable runnable) {
        if(runnable instanceof OwnedTask task)task.discard();
    }
    private static final class OwnedTask implements Runnable {
        private final boolean security;private final long submitted;private final LongSupplier epoch;
        private final BooleanSupplier closed;private final Runnable action,discarded;private final AtomicBoolean consumed=new AtomicBoolean();
        private OwnedTask(boolean security,long submitted,LongSupplier epoch,BooleanSupplier closed,Runnable action,Runnable discarded){this.security=security;this.submitted=submitted;this.epoch=epoch;this.closed=closed;this.action=action;this.discarded=discarded;}
        public void run(){if(!consumed.compareAndSet(false,true))return;if(!security&&(closed.getAsBoolean()||epoch.getAsLong()!=submitted)){discarded.run();return;}action.run();}
        private void discard(){if(!security&&consumed.compareAndSet(false,true))discarded.run();}
    }
}
