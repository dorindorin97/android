package org.csploit.android.core;

import org.csploit.android.events.Event;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for EventManager.
 * Tests event publishing, subscription, and interception.
 */
@DisplayName("EventManager Tests")
public class EventManagerTest {

    private EventManager manager;

    @BeforeEach
    void setUp() {
        manager = new EventManager();
    }

    @Test
    @DisplayName("Should create EventManager with no listeners")
    void testInitialState() {
        assertThat(manager.getTotalListenerCount()).isZero();
        assertThat(manager.getStatusSummary()).contains("EventManager");
    }

    @Test
    @DisplayName("Should throw exception when subscribing with null event type")
    void testSubscribeNullEventType() {
        assertThatThrownBy(() -> manager.subscribe(null, event -> {}))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Should throw exception when subscribing with null listener")
    void testSubscribeNullListener() {
        assertThatThrownBy(() -> manager.subscribe(TestEvent.class, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Should subscribe to events")
    void testSubscribeToEvent() {
        EventManager.EventListener<TestEvent> listener = event -> {};

        manager.subscribe(TestEvent.class, listener);

        assertThat(manager.getListenerCount(TestEvent.class)).isEqualTo(1);
        assertThat(manager.hasListeners(TestEvent.class)).isTrue();
    }

    @Test
    @DisplayName("Should unsubscribe from events")
    void testUnsubscribeFromEvent() {
        EventManager.EventListener<TestEvent> listener = event -> {};

        manager.subscribe(TestEvent.class, listener);
        boolean removed = manager.unsubscribe(TestEvent.class, listener);

        assertThat(removed).isTrue();
        assertThat(manager.getListenerCount(TestEvent.class)).isZero();
    }

    @Test
    @DisplayName("Should return false when unsubscribing non-existent listener")
    void testUnsubscribeNonExistentListener() {
        EventManager.EventListener<TestEvent> listener = event -> {};

        boolean removed = manager.unsubscribe(TestEvent.class, listener);
        assertThat(removed).isFalse();
    }

    @Test
    @DisplayName("Should publish events to subscribers")
    void testPublishEvent() {
        TestEventCapture capture = new TestEventCapture();
        EventManager.EventListener<TestEvent> listener = event -> capture.capturedEvent = event;

        manager.subscribe(TestEvent.class, listener);

        TestEvent testEvent = new TestEvent("test");
        manager.publish(testEvent);

        assertThat(capture.capturedEvent).isEqualTo(testEvent);
    }

    @Test
    @DisplayName("Should throw exception when publishing null event")
    void testPublishNullEvent() {
        assertThatThrownBy(() -> manager.publish(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Should handle multiple subscribers")
    void testMultipleSubscribers() {
        TestEventCapture capture1 = new TestEventCapture();
        TestEventCapture capture2 = new TestEventCapture();

        EventManager.EventListener<TestEvent> listener1 = event -> capture1.capturedEvent = event;
        EventManager.EventListener<TestEvent> listener2 = event -> capture2.capturedEvent = event;

        manager.subscribe(TestEvent.class, listener1);
        manager.subscribe(TestEvent.class, listener2);

        TestEvent testEvent = new TestEvent("test");
        manager.publish(testEvent);

        assertThat(capture1.capturedEvent).isEqualTo(testEvent);
        assertThat(capture2.capturedEvent).isEqualTo(testEvent);
    }

    @Test
    @DisplayName("Should clear all listeners for specific event type")
    void testClearListenersForType() {
        manager.subscribe(TestEvent.class, event -> {});
        manager.subscribe(TestEvent.class, event -> {});

        assertThat(manager.getListenerCount(TestEvent.class)).isEqualTo(2);

        manager.clearListeners(TestEvent.class);

        assertThat(manager.getListenerCount(TestEvent.class)).isZero();
    }

    @Test
    @DisplayName("Should clear all listeners and interceptors")
    void testClearAll() {
        manager.subscribe(TestEvent.class, event -> {});
        manager.addInterceptor(event -> true);

        assertThat(manager.getTotalListenerCount()).isGreaterThan(0);

        manager.clearAll();

        assertThat(manager.getTotalListenerCount()).isZero();
        assertThat(manager.hasListeners(TestEvent.class)).isFalse();
    }

    @Test
    @DisplayName("Should add event interceptor")
    void testAddInterceptor() {
        EventManager.EventInterceptor interceptor = event -> true;
        manager.addInterceptor(interceptor);

        // Verify through status summary
        String summary = manager.getStatusSummary();
        assertThat(summary).contains("Interceptors: 1");
    }

    @Test
    @DisplayName("Should throw exception when adding null interceptor")
    void testAddNullInterceptor() {
        assertThatThrownBy(() -> manager.addInterceptor(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Should remove event interceptor")
    void testRemoveInterceptor() {
        EventManager.EventInterceptor interceptor = event -> true;
        manager.addInterceptor(interceptor);

        boolean removed = manager.removeInterceptor(interceptor);
        assertThat(removed).isTrue();
    }

    @Test
    @DisplayName("Should allow interceptor to block events")
    void testInterceptorBlocksEvent() {
        TestEventCapture capture = new TestEventCapture();

        manager.subscribe(TestEvent.class, event -> capture.capturedEvent = event);
        manager.addInterceptor(event -> false); // Block all events

        TestEvent testEvent = new TestEvent("test");
        manager.publish(testEvent);

        assertThat(capture.capturedEvent).isNull();
    }

    @Test
    @DisplayName("Should allow interceptor to allow events")
    void testInterceptorAllowsEvent() {
        TestEventCapture capture = new TestEventCapture();

        manager.subscribe(TestEvent.class, event -> capture.capturedEvent = event);
        manager.addInterceptor(event -> true); // Allow all events

        TestEvent testEvent = new TestEvent("test");
        manager.publish(testEvent);

        assertThat(capture.capturedEvent).isEqualTo(testEvent);
    }

    @Test
    @DisplayName("Should handle listener exceptions gracefully")
    void testListenerException() {
        EventManager.EventListener<TestEvent> failingListener = event -> {
            throw new RuntimeException("Listener failed");
        };
        EventManager.EventListener<TestEvent> successListener = new TestEventCapture()::captureEvent;

        manager.subscribe(TestEvent.class, failingListener);
        manager.subscribe(TestEvent.class, successListener);

        // Should not throw
        assertThatCode(() -> manager.publish(new TestEvent("test")))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("Should provide total listener count")
    void testGetTotalListenerCount() {
        manager.subscribe(TestEvent.class, event -> {});
        manager.subscribe(TestEvent.class, event -> {});
        manager.subscribe(AnotherEvent.class, event -> {});

        assertThat(manager.getTotalListenerCount()).isEqualTo(3);
    }

    /**
     * Mock Event for testing.
     */
    static class TestEvent implements Event {
        private final String data;

        TestEvent(String data) {
            this.data = data;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof TestEvent)) return false;
            TestEvent that = (TestEvent) o;
            return java.util.Objects.equals(data, that.data);
        }

        @Override
        public int hashCode() {
            return java.util.Objects.hash(data);
        }
    }

    /**
     * Another mock Event for testing multiple event types.
     */
    static class AnotherEvent implements Event {
    }

    /**
     * Test helper to capture events.
     */
    static class TestEventCapture {
        TestEvent capturedEvent;

        void captureEvent(TestEvent event) {
            this.capturedEvent = event;
        }
    }
}
