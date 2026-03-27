package org.csploit.android.core;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.List;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for PluginManager.
 * Tests plugin registration, lookup, and lifecycle management.
 */
@DisplayName("PluginManager Tests")
public class PluginManagerTest {

    private PluginManager manager;

    @BeforeEach
    void setUp() {
        manager = new PluginManager();
    }

    @Test
    @DisplayName("Should create PluginManager with empty plugin list")
    void testInitialState() {
        assertThat(manager.getPluginCount()).isZero();
        assertThat(manager.getCurrentPlugin()).isNull();
        assertThat(manager.getAllPlugins()).isEmpty();
    }

    @Test
    @DisplayName("Should throw exception when registering null plugin")
    void testRegisterNullPlugin() {
        assertThatThrownBy(() -> manager.registerPlugin(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cannot be null");
    }

    @Test
    @DisplayName("Should check if plugin is registered")
    void testIsPluginRegistered() {
        // Create mock plugin for testing
        MockPlugin plugin = new MockPlugin();

        assertThat(manager.isPluginRegistered(plugin)).isFalse();

        manager.registerPlugin(plugin);
        assertThat(manager.isPluginRegistered(plugin)).isTrue();
    }

    @Test
    @DisplayName("Should handle duplicate registration gracefully")
    void testDuplicateRegistration() {
        MockPlugin plugin = new MockPlugin();

        manager.registerPlugin(plugin);
        assertThat(manager.getPluginCount()).isEqualTo(1);

        manager.registerPlugin(plugin);
        assertThat(manager.getPluginCount()).isEqualTo(1);
    }

    @Test
    @DisplayName("Should unregister plugin")
    void testUnregisterPlugin() {
        MockPlugin plugin = new MockPlugin();

        manager.registerPlugin(plugin);
        assertThat(manager.getPluginCount()).isEqualTo(1);

        boolean removed = manager.unregisterPlugin(plugin);
        assertThat(removed).isTrue();
        assertThat(manager.getPluginCount()).isZero();
    }

    @Test
    @DisplayName("Should return false when unregistering non-existent plugin")
    void testUnregisterNonExistentPlugin() {
        MockPlugin plugin = new MockPlugin();
        boolean removed = manager.unregisterPlugin(plugin);
        assertThat(removed).isFalse();
    }

    @Test
    @DisplayName("Should set current plugin if registered")
    void testSetCurrentPlugin() {
        MockPlugin plugin = new MockPlugin();

        manager.registerPlugin(plugin);
        boolean success = manager.setCurrentPlugin(plugin);

        assertThat(success).isTrue();
        assertThat(manager.getCurrentPlugin()).isEqualTo(plugin);
    }

    @Test
    @DisplayName("Should reject setting unregistered plugin as current")
    void testSetUnregisteredPluginAsCurrent() {
        MockPlugin plugin = new MockPlugin();

        boolean success = manager.setCurrentPlugin(plugin);
        assertThat(success).isFalse();
        assertThat(manager.getCurrentPlugin()).isNull();
    }

    @Test
    @DisplayName("Should allow clearing current plugin")
    void testClearCurrentPlugin() {
        MockPlugin plugin = new MockPlugin();

        manager.registerPlugin(plugin);
        manager.setCurrentPlugin(plugin);
        manager.setCurrentPlugin(null);

        assertThat(manager.getCurrentPlugin()).isNull();
    }

    @Test
    @DisplayName("Should find plugin by class name")
    void testFindPluginByClassName() {
        MockPlugin plugin = new MockPlugin();
        manager.registerPlugin(plugin);

        IPlugin found = manager.findPluginByClass(MockPlugin.class.getName());
        assertThat(found).isEqualTo(plugin);
    }

    @Test
    @DisplayName("Should return null for non-existent class name")
    void testFindNonExistentByClassName() {
        IPlugin found = manager.findPluginByClass("com.example.NonExistent");
        assertThat(found).isNull();
    }

    @Test
    @DisplayName("Should find plugin by simple class name")
    void testFindPluginBySimpleName() {
        MockPlugin plugin = new MockPlugin();
        manager.registerPlugin(plugin);

        IPlugin found = manager.findPluginBySimpleName("MockPlugin");
        assertThat(found).isEqualTo(plugin);
    }

    @Test
    @DisplayName("Should return null for non-existent simple name")
    void testFindNonExistentBySimpleName() {
        IPlugin found = manager.findPluginBySimpleName("NonExistent");
        assertThat(found).isNull();
    }

    @Test
    @DisplayName("Should clear all plugins")
    void testClearAllPlugins() {
        MockPlugin plugin1 = new MockPlugin();
        MockPlugin plugin2 = new MockPlugin();

        manager.registerPlugin(plugin1);
        manager.registerPlugin(plugin2);
        manager.setCurrentPlugin(plugin1);

        manager.clearAllPlugins();

        assertThat(manager.getPluginCount()).isZero();
        assertThat(manager.getCurrentPlugin()).isNull();
    }

    @Test
    @DisplayName("Should return unmodifiable plugin list")
    void testGetAllPluginsIsUnmodifiable() {
        MockPlugin plugin = new MockPlugin();
        manager.registerPlugin(plugin);

        var plugins = manager.getAllPlugins();
        assertThatThrownBy(() -> plugins.add(new MockPlugin()))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("Should provide status summary")
    void testStatusSummary() {
        MockPlugin plugin = new MockPlugin();
        manager.registerPlugin(plugin);
        manager.setCurrentPlugin(plugin);

        String summary = manager.getStatusSummary();
        assertThat(summary).contains("PluginManager");
        assertThat(summary).contains("Registered: 1");
        assertThat(summary).contains("MockPlugin");
    }

    @Test
    @DisplayName("Should manage multiple plugins")
    void testMultiplePlugins() {
        MockPlugin plugin1 = new MockPlugin();
        MockPlugin plugin2 = new MockPlugin();
        MockPlugin plugin3 = new MockPlugin();

        manager.registerPlugin(plugin1);
        manager.registerPlugin(plugin2);
        manager.registerPlugin(plugin3);

        assertThat(manager.getPluginCount()).isEqualTo(3);
        assertThat(manager.getAllPlugins()).containsExactly(plugin1, plugin2, plugin3);
    }

    /**
     * Mock Plugin for testing.
     */
    static class MockPlugin implements IPlugin {
        @Override
        public void onTargetSelected(Object target) {
            // No-op for testing
        }

        @Override
        public boolean supportsTargetType(String targetType) {
            return true;
        }

        @Override
        public String getPluginName() {
            return "MockPlugin";
        }
    }
}
