/*
 * This file is part of cSploit.
 *
 * cSploit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cSploit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cSploit. If not, see <http://www.gnu.org/licenses/>.
 */
package org.csploit.android.helpers;

import android.graphics.Bitmap;
import org.csploit.android.helpers.LoggingHelper;
import android.graphics.Canvas;
import org.csploit.android.helpers.LoggingHelper;
import android.graphics.Color;
import org.csploit.android.helpers.LoggingHelper;
import android.graphics.Paint;
import org.csploit.android.helpers.LoggingHelper;
import android.graphics.Path;
import org.csploit.android.helpers.LoggingHelper;
import android.graphics.RectF;
import org.csploit.android.helpers.LoggingHelper;

import androidx.annotation.NonNull;
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.Nullable;
import org.csploit.android.helpers.LoggingHelper;

import org.csploit.android.core.System;
import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.net.Target;
import org.csploit.android.helpers.LoggingHelper;

import java.io.File;
import org.csploit.android.helpers.LoggingHelper;
import java.io.FileOutputStream;
import org.csploit.android.helpers.LoggingHelper;
import java.io.IOException;
import org.csploit.android.helpers.LoggingHelper;
import java.util.ArrayList;
import org.csploit.android.helpers.LoggingHelper;
import java.util.HashMap;
import org.csploit.android.helpers.LoggingHelper;
import java.util.List;
import org.csploit.android.helpers.LoggingHelper;
import java.util.Map;
import org.csploit.android.helpers.LoggingHelper;

/**
 * NetworkTopologyHelper - Generate network topology visualizations
 *
 * Creates visual representations of discovered network topology including:
 * - Device nodes with icons based on type
 * - Connection lines showing network relationships
 * - Gateway highlighting
 * - Color-coded status indicators
 *
 * Output formats:
 * - Bitmap image for display
 * - SVG export for web/scalable display
 * - JSON data for custom rendering
 */
public final class NetworkTopologyHelper {
    private static final String TAG = "NetworkTopologyHelper";

    // Node colors
    private static final int COLOR_GATEWAY = Color.parseColor("#4CAF50");
    private static final int COLOR_ROUTER = Color.parseColor("#2196F3");
    private static final int COLOR_SERVER = Color.parseColor("#9C27B0");
    private static final int COLOR_WORKSTATION = Color.parseColor("#FF9800");
    private static final int COLOR_MOBILE = Color.parseColor("#00BCD4");
    private static final int COLOR_IOT = Color.parseColor("#795548");
    private static final int COLOR_UNKNOWN = Color.parseColor("#9E9E9E");
    private static final int COLOR_VULNERABLE = Color.parseColor("#F44336");
    private static final int COLOR_CONNECTION = Color.parseColor("#BDBDBD");
    private static final int COLOR_BACKGROUND = Color.parseColor("#FAFAFA");

    // Node sizes
    private static final float NODE_RADIUS_GATEWAY = 45f;
    private static final float NODE_RADIUS_NORMAL = 35f;
    private static final float NODE_RADIUS_SMALL = 25f;

    /**
     * Node representation for topology
     */
    public static class TopologyNode {
        public final String id;
        public final String label;
        public final String ip;
        public final String mac;
        public final NodeType type;
        public final boolean isGateway;
        public final boolean isVulnerable;
        public final int openPortCount;
        public float x;
        public float y;

        public TopologyNode(Target target, boolean gateway) {
            this.id = target.getUuid();
            this.ip = target.getCommandLineRepresentation();
            this.mac = target.getHardwareAddress() != null ?
                    NetworkHelper.bytesToMac(target.getHardwareAddress()) : "";
            this.label = target.getAlias() != null ? target.getAlias() :
                    (target.getHostname() != null ? target.getHostname() : ip);
            this.type = determineNodeType(target);
            this.isGateway = gateway;
            this.isVulnerable = !target.getExploits().isEmpty();
            this.openPortCount = target.hasOpenPorts() ? target.getOpenPorts().size() : 0;
        }

        private NodeType determineNodeType(Target target) {
            String deviceType = target.getDeviceType();
            String os = target.getDeviceOS();

            if (deviceType != null) {
                deviceType = deviceType.toLowerCase();
                if (deviceType.contains("router") || deviceType.contains("gateway")) {
                    return NodeType.ROUTER;
                }
                if (deviceType.contains("server")) {
                    return NodeType.SERVER;
                }
                if (deviceType.contains("phone") || deviceType.contains("mobile") ||
                    deviceType.contains("android") || deviceType.contains("ios")) {
                    return NodeType.MOBILE;
                }
                if (deviceType.contains("iot") || deviceType.contains("camera") ||
                    deviceType.contains("sensor") || deviceType.contains("smart")) {
                    return NodeType.IOT;
                }
            }

            if (os != null) {
                os = os.toLowerCase();
                if (os.contains("linux") && (os.contains("server") || os.contains("ubuntu server"))) {
                    return NodeType.SERVER;
                }
                if (os.contains("windows server")) {
                    return NodeType.SERVER;
                }
                if (os.contains("android") || os.contains("ios")) {
                    return NodeType.MOBILE;
                }
            }

            // Check by open ports
            if (target.hasOpenPorts()) {
                for (Target.Port port : target.getOpenPorts()) {
                    int num = port.getNumber();
                    if (num == 80 || num == 443 || num == 8080 || num == 22 || num == 21) {
                        return NodeType.SERVER;
                    }
                }
            }

            return NodeType.WORKSTATION;
        }
    }

    public enum NodeType {
        GATEWAY, ROUTER, SERVER, WORKSTATION, MOBILE, IOT, UNKNOWN
    }

    private NetworkTopologyHelper() {}

    /**
     * Generate topology data from current targets
     *
     * @return List of topology nodes
     */
    @NonNull
    public static List<TopologyNode> generateTopologyData() {
        List<TopologyNode> nodes = new ArrayList<>();
        List<Target> targets = System.getTargets();

        for (Target target : targets) {
            boolean isGateway = target.isRouter();
            nodes.add(new TopologyNode(target, isGateway));
        }

        return nodes;
    }

    /**
     * Generate a bitmap visualization of the network topology
     *
     * @param width Bitmap width
     * @param height Bitmap height
     * @return Bitmap with topology visualization
     */
    @NonNull
    public static Bitmap generateTopologyBitmap(int width, int height) {
        List<TopologyNode> nodes = generateTopologyData();
        calculateNodePositions(nodes, width, height);

        Bitmap bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(bitmap);

        // Draw background
        canvas.drawColor(COLOR_BACKGROUND);

        Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);

        // Find gateway node
        TopologyNode gatewayNode = null;
        for (TopologyNode node : nodes) {
            if (node.isGateway) {
                gatewayNode = node;
                break;
            }
        }

        // Draw connections from gateway to all nodes
        if (gatewayNode != null) {
            paint.setColor(COLOR_CONNECTION);
            paint.setStrokeWidth(2f);
            paint.setStyle(Paint.Style.STROKE);

            for (TopologyNode node : nodes) {
                if (!node.isGateway) {
                    canvas.drawLine(gatewayNode.x, gatewayNode.y, node.x, node.y, paint);
                }
            }
        }

        // Draw nodes
        for (TopologyNode node : nodes) {
            drawNode(canvas, paint, node);
        }

        return bitmap;
    }

    /**
     * Generate SVG representation of the topology
     *
     * @param width SVG width
     * @param height SVG height
     * @return SVG string
     */
    @NonNull
    public static String generateTopologySvg(int width, int height) {
        List<TopologyNode> nodes = generateTopologyData();
        calculateNodePositions(nodes, width, height);

        StringBuilder svg = new StringBuilder();
        svg.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        svg.append("<svg xmlns=\"http://www.w3.org/2000/svg\" ");
        svg.append("width=\"").append(width).append("\" height=\"").append(height).append("\">\n");

        // Styles
        svg.append("<defs>\n");
        svg.append("<style>\n");
        svg.append(".node-label { font-family: Arial, sans-serif; font-size: 12px; text-anchor: middle; }\n");
        svg.append(".node-ip { font-family: Arial, sans-serif; font-size: 10px; text-anchor: middle; fill: #666; }\n");
        svg.append("</style>\n");
        svg.append("</defs>\n");

        // Background
        svg.append("<rect width=\"100%\" height=\"100%\" fill=\"#FAFAFA\"/>\n");

        // Find gateway
        TopologyNode gatewayNode = null;
        for (TopologyNode node : nodes) {
            if (node.isGateway) {
                gatewayNode = node;
                break;
            }
        }

        // Draw connections
        if (gatewayNode != null) {
            svg.append("<g stroke=\"#BDBDBD\" stroke-width=\"2\" fill=\"none\">\n");
            for (TopologyNode node : nodes) {
                if (!node.isGateway) {
                    svg.append("<line x1=\"").append((int)gatewayNode.x).append("\" ");
                    svg.append("y1=\"").append((int)gatewayNode.y).append("\" ");
                    svg.append("x2=\"").append((int)node.x).append("\" ");
                    svg.append("y2=\"").append((int)node.y).append("\"/>\n");
                }
            }
            svg.append("</g>\n");
        }

        // Draw nodes
        for (TopologyNode node : nodes) {
            float radius = node.isGateway ? NODE_RADIUS_GATEWAY : NODE_RADIUS_NORMAL;
            String color = getNodeColorHex(node);

            svg.append("<g>\n");

            // Node circle
            svg.append("<circle cx=\"").append((int)node.x).append("\" ");
            svg.append("cy=\"").append((int)node.y).append("\" ");
            svg.append("r=\"").append((int)radius).append("\" ");
            svg.append("fill=\"").append(color).append("\" ");
            if (node.isVulnerable) {
                svg.append("stroke=\"#F44336\" stroke-width=\"3\"");
            }
            svg.append("/>\n");

            // Label
            svg.append("<text x=\"").append((int)node.x).append("\" ");
            svg.append("y=\"").append((int)(node.y + radius + 15)).append("\" ");
            svg.append("class=\"node-label\">").append(escapeXml(truncateLabel(node.label))).append("</text>\n");

            // IP
            svg.append("<text x=\"").append((int)node.x).append("\" ");
            svg.append("y=\"").append((int)(node.y + radius + 28)).append("\" ");
            svg.append("class=\"node-ip\">").append(node.ip).append("</text>\n");

            // Icon text
            svg.append("<text x=\"").append((int)node.x).append("\" ");
            svg.append("y=\"").append((int)(node.y + 5)).append("\" ");
            svg.append("text-anchor=\"middle\" fill=\"white\" font-size=\"20\">");
            svg.append(getNodeIcon(node)).append("</text>\n");

            svg.append("</g>\n");
        }

        svg.append("</svg>");
        return svg.toString();
    }

    /**
     * Export topology to an HTML file with interactive features
     *
     * @param width Canvas width
     * @param height Canvas height
     * @return HTML string
     */
    @NonNull
    public static String generateTopologyHtml(int width, int height) {
        List<TopologyNode> nodes = generateTopologyData();

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n<html>\n<head>\n");
        html.append("<meta charset=\"UTF-8\">\n");
        html.append("<title>Network Topology - cSploit</title>\n");
        html.append("<style>\n");
        html.append("body { margin: 0; font-family: Arial, sans-serif; background: #f5f5f5; }\n");
        html.append("#canvas { display: block; margin: 20px auto; border: 1px solid #ddd; background: #fafafa; }\n");
        html.append("#info { position: fixed; right: 20px; top: 20px; background: white; padding: 15px; ");
        html.append("border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); min-width: 200px; display: none; }\n");
        html.append("#info h3 { margin: 0 0 10px 0; }\n");
        html.append(".legend { position: fixed; left: 20px; bottom: 20px; background: white; padding: 15px; ");
        html.append("border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }\n");
        html.append(".legend-item { display: flex; align-items: center; margin: 5px 0; }\n");
        html.append(".legend-color { width: 20px; height: 20px; border-radius: 50%; margin-right: 10px; }\n");
        html.append("</style>\n</head>\n<body>\n");

        html.append("<canvas id=\"canvas\" width=\"").append(width).append("\" height=\"").append(height).append("\"></canvas>\n");

        html.append("<div id=\"info\"></div>\n");

        // Legend
        html.append("<div class=\"legend\">\n");
        html.append("<strong>Legend</strong>\n");
        html.append("<div class=\"legend-item\"><div class=\"legend-color\" style=\"background:#4CAF50\"></div>Gateway</div>\n");
        html.append("<div class=\"legend-item\"><div class=\"legend-color\" style=\"background:#2196F3\"></div>Router</div>\n");
        html.append("<div class=\"legend-item\"><div class=\"legend-color\" style=\"background:#9C27B0\"></div>Server</div>\n");
        html.append("<div class=\"legend-item\"><div class=\"legend-color\" style=\"background:#FF9800\"></div>Workstation</div>\n");
        html.append("<div class=\"legend-item\"><div class=\"legend-color\" style=\"background:#00BCD4\"></div>Mobile</div>\n");
        html.append("<div class=\"legend-item\"><div class=\"legend-color\" style=\"background:#795548\"></div>IoT Device</div>\n");
        html.append("<div class=\"legend-item\"><div class=\"legend-color\" style=\"background:#F44336;border:2px solid #F44336\"></div>Vulnerable</div>\n");
        html.append("</div>\n");

        // JavaScript for rendering
        html.append("<script>\n");
        html.append("const nodes = ").append(nodesToJson(nodes)).append(";\n");
        html.append("const canvas = document.getElementById('canvas');\n");
        html.append("const ctx = canvas.getContext('2d');\n");
        html.append("const info = document.getElementById('info');\n");

        html.append("function getColor(node) {\n");
        html.append("  if (node.isGateway) return '#4CAF50';\n");
        html.append("  switch(node.type) {\n");
        html.append("    case 'ROUTER': return '#2196F3';\n");
        html.append("    case 'SERVER': return '#9C27B0';\n");
        html.append("    case 'MOBILE': return '#00BCD4';\n");
        html.append("    case 'IOT': return '#795548';\n");
        html.append("    case 'WORKSTATION': return '#FF9800';\n");
        html.append("    default: return '#9E9E9E';\n");
        html.append("  }\n");
        html.append("}\n");

        html.append("function layoutNodes() {\n");
        html.append("  const centerX = canvas.width / 2, centerY = canvas.height / 2;\n");
        html.append("  const gateway = nodes.find(n => n.isGateway);\n");
        html.append("  if (gateway) { gateway.x = centerX; gateway.y = centerY - 100; }\n");
        html.append("  const others = nodes.filter(n => !n.isGateway);\n");
        html.append("  const angleStep = (2 * Math.PI) / others.length;\n");
        html.append("  others.forEach((n, i) => {\n");
        html.append("    n.x = centerX + Math.cos(angleStep * i - Math.PI/2) * 200;\n");
        html.append("    n.y = centerY + Math.sin(angleStep * i - Math.PI/2) * 200 + 50;\n");
        html.append("  });\n");
        html.append("}\n");

        html.append("function draw() {\n");
        html.append("  ctx.fillStyle = '#fafafa'; ctx.fillRect(0, 0, canvas.width, canvas.height);\n");
        html.append("  const gateway = nodes.find(n => n.isGateway);\n");
        html.append("  if (gateway) {\n");
        html.append("    ctx.strokeStyle = '#BDBDBD'; ctx.lineWidth = 2;\n");
        html.append("    nodes.filter(n => !n.isGateway).forEach(n => {\n");
        html.append("      ctx.beginPath(); ctx.moveTo(gateway.x, gateway.y); ctx.lineTo(n.x, n.y); ctx.stroke();\n");
        html.append("    });\n");
        html.append("  }\n");
        html.append("  nodes.forEach(n => {\n");
        html.append("    const r = n.isGateway ? 45 : 35;\n");
        html.append("    ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, 2*Math.PI);\n");
        html.append("    ctx.fillStyle = getColor(n); ctx.fill();\n");
        html.append("    if (n.isVulnerable) { ctx.strokeStyle = '#F44336'; ctx.lineWidth = 3; ctx.stroke(); }\n");
        html.append("    ctx.fillStyle = '#333'; ctx.font = '12px Arial'; ctx.textAlign = 'center';\n");
        html.append("    ctx.fillText(n.label.substring(0,15), n.x, n.y + r + 15);\n");
        html.append("    ctx.fillStyle = '#666'; ctx.font = '10px Arial';\n");
        html.append("    ctx.fillText(n.ip, n.x, n.y + r + 28);\n");
        html.append("  });\n");
        html.append("}\n");

        html.append("canvas.onclick = (e) => {\n");
        html.append("  const rect = canvas.getBoundingClientRect();\n");
        html.append("  const x = e.clientX - rect.left, y = e.clientY - rect.top;\n");
        html.append("  const clicked = nodes.find(n => Math.hypot(n.x-x, n.y-y) < (n.isGateway ? 45 : 35));\n");
        html.append("  if (clicked) {\n");
        html.append("    info.innerHTML = '<h3>'+clicked.label+'</h3>';\n");
        html.append("    info.innerHTML += '<p><b>IP:</b> '+clicked.ip+'</p>';\n");
        html.append("    if (clicked.mac) info.innerHTML += '<p><b>MAC:</b> '+clicked.mac+'</p>';\n");
        html.append("    info.innerHTML += '<p><b>Type:</b> '+clicked.type+'</p>';\n");
        html.append("    info.innerHTML += '<p><b>Open Ports:</b> '+clicked.openPortCount+'</p>';\n");
        html.append("    if (clicked.isVulnerable) info.innerHTML += '<p style=\"color:#F44336\"><b>⚠ Vulnerable</b></p>';\n");
        html.append("    info.style.display = 'block';\n");
        html.append("  } else { info.style.display = 'none'; }\n");
        html.append("};\n");

        html.append("layoutNodes(); draw();\n");
        html.append("</script>\n</body>\n</html>");

        return html.toString();
    }

    /**
     * Save topology as PNG image
     *
     * @param file Output file
     * @param width Image width
     * @param height Image height
     * @return true if successful
     */
    public static boolean saveTopologyAsPng(@NonNull File file, int width, int height) {
        Bitmap bitmap = generateTopologyBitmap(width, height);
        FileOutputStream out = null;

        try {
            out = new FileOutputStream(file);
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, out);
            return true;
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Failed to save topology PNG", e);
            return false;
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
            bitmap.recycle();
        }
    }

    // ==================== Private Helper Methods ====================

    private static void calculateNodePositions(List<TopologyNode> nodes, int width, int height) {
        float centerX = width / 2f;
        float centerY = height / 2f;
        float radius = Math.min(width, height) / 3f;

        // Position gateway at center-top
        TopologyNode gateway = null;
        List<TopologyNode> others = new ArrayList<>();
        for (TopologyNode node : nodes) {
            if (node.isGateway) {
                gateway = node;
            } else {
                others.add(node);
            }
        }

        if (gateway != null) {
            gateway.x = centerX;
            gateway.y = centerY - radius / 2;
        }

        // Position other nodes in a circle
        int count = others.size();
        if (count > 0) {
            double angleStep = 2 * Math.PI / count;
            for (int i = 0; i < count; i++) {
                double angle = angleStep * i - Math.PI / 2;
                others.get(i).x = centerX + (float)(radius * Math.cos(angle));
                others.get(i).y = centerY + (float)(radius * Math.sin(angle)) + 50;
            }
        }
    }

    private static void drawNode(Canvas canvas, Paint paint, TopologyNode node) {
        float radius = node.isGateway ? NODE_RADIUS_GATEWAY : NODE_RADIUS_NORMAL;

        // Draw node circle
        paint.setStyle(Paint.Style.FILL);
        paint.setColor(getNodeColor(node));
        canvas.drawCircle(node.x, node.y, radius, paint);

        // Draw vulnerability indicator
        if (node.isVulnerable) {
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeWidth(3f);
            paint.setColor(COLOR_VULNERABLE);
            canvas.drawCircle(node.x, node.y, radius, paint);
        }

        // Draw label
        paint.setStyle(Paint.Style.FILL);
        paint.setColor(Color.DKGRAY);
        paint.setTextSize(24f);
        paint.setTextAlign(Paint.Align.CENTER);
        String label = truncateLabel(node.label);
        canvas.drawText(label, node.x, node.y + radius + 20, paint);

        // Draw IP
        paint.setColor(Color.GRAY);
        paint.setTextSize(20f);
        canvas.drawText(node.ip, node.x, node.y + radius + 40, paint);

        // Draw icon in circle
        paint.setColor(Color.WHITE);
        paint.setTextSize(32f);
        canvas.drawText(getNodeIcon(node), node.x, node.y + 10, paint);
    }

    private static int getNodeColor(TopologyNode node) {
        if (node.isGateway) return COLOR_GATEWAY;
        switch (node.type) {
            case ROUTER: return COLOR_ROUTER;
            case SERVER: return COLOR_SERVER;
            case MOBILE: return COLOR_MOBILE;
            case IOT: return COLOR_IOT;
            case WORKSTATION: return COLOR_WORKSTATION;
            default: return COLOR_UNKNOWN;
        }
    }

    private static String getNodeColorHex(TopologyNode node) {
        int color = getNodeColor(node);
        return String.format("#%06X", (0xFFFFFF & color));
    }

    private static String getNodeIcon(TopologyNode node) {
        if (node.isGateway) return "⬢";
        switch (node.type) {
            case ROUTER: return "◉";
            case SERVER: return "▣";
            case MOBILE: return "◧";
            case IOT: return "◈";
            case WORKSTATION: return "▢";
            default: return "○";
        }
    }

    private static String truncateLabel(String label) {
        if (label.length() > 15) {
            return label.substring(0, 12) + "...";
        }
        return label;
    }

    private static String nodesToJson(List<TopologyNode> nodes) {
        StringBuilder json = new StringBuilder("[");
        boolean first = true;
        for (TopologyNode node : nodes) {
            if (!first) json.append(",");
            first = false;
            json.append("{");
            json.append("\"id\":\"").append(escapeJson(node.id)).append("\",");
            json.append("\"label\":\"").append(escapeJson(node.label)).append("\",");
            json.append("\"ip\":\"").append(node.ip).append("\",");
            json.append("\"mac\":\"").append(node.mac).append("\",");
            json.append("\"type\":\"").append(node.type.name()).append("\",");
            json.append("\"isGateway\":").append(node.isGateway).append(",");
            json.append("\"isVulnerable\":").append(node.isVulnerable).append(",");
            json.append("\"openPortCount\":").append(node.openPortCount);
            json.append("}");
        }
        json.append("]");
        return json.toString();
    }

    private static String escapeJson(String text) {
        if (text == null) return "";
        return text.replace("\\", "\\\\")
                   .replace("\"", "\\\"")
                   .replace("\n", "\\n");
    }

    private static String escapeXml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;");
    }
}
