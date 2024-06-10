package org.khoasoma.untitled;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerLoginEvent;
import org.bukkit.plugin.java.JavaPlugin;
import org.json.JSONObject;

import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class CustomAC extends JavaPlugin implements Listener {
    private int maxRequestsPerMinute;
    private long blockTimeMs;
    private int maxConcurrentConnections;
    private long minTimeBetweenConnectionsMs;
    private String iphubApiKey;

    private final Map<String, Integer> requestCounts = new ConcurrentHashMap<>();
    private final Map<String, Long> blockList = new ConcurrentHashMap<>();
    private final Map<String, Long> lastRequestTime = new ConcurrentHashMap<>();
    private final Map<String, Integer> concurrentConnections = new ConcurrentHashMap<>();
    private final Set<String> whitelist = ConcurrentHashMap.newKeySet();
    private final Set<String> blacklist = ConcurrentHashMap.newKeySet();
    private Logger logger;

    @Override
    public void onEnable() {
        // Khởi động plugin
        saveDefaultConfig();
        FileConfiguration config = getConfig();
        maxRequestsPerMinute = config.getInt("maxRequestsPerMinute", 100);
        blockTimeMs = config.getLong("blockTimeMs", 60000);
        maxConcurrentConnections = config.getInt("maxConcurrentConnections", 10);
        minTimeBetweenConnectionsMs = config.getLong("minTimeBetweenConnectionsMs", 1000);
        iphubApiKey = config.getString("iphubApiKey");

        getServer().getPluginManager().registerEvents(this, this);
        logger = getLogger();
        logger.info("CustomAC đã được bật.");

        // Bắt đầu giám sát tấn công DDOS
        startDdosProtectionMonitor();
    }

    @Override
    public void onDisable() {
        // Tắt plugin
        logger.info("CustomAC đã được tắt.");
    }

    @EventHandler
    public void onPlayerLogin(PlayerLoginEvent event) {
        String ip = event.getAddress().getHostAddress();
        long currentTime = System.currentTimeMillis();

        // Kiểm tra IP có trên whitelist không
        if (whitelist.contains(ip)) {
            return;
        }

        // Kiểm tra IP có trên blacklist không
        if (blacklist.contains(ip)) {
            event.disallow(PlayerLoginEvent.Result.KICK_OTHER, ChatColor.RED + "Bạn bị đưa vào danh sách đen.");
            logger.warning("IP đã bị đưa vào danh sách đen: " + ip);
            return;
        }

        // Kiểm tra IP có trong danh sách block không
        if (isBlocked(ip, currentTime)) {
            event.disallow(PlayerLoginEvent.Result.KICK_OTHER, ChatColor.RED + "Bạn bị tạm thời chặn do hoạt động đáng ngờ.");
            logger.warning("IP bị chặn: " + ip);
            return;
        }

        // Kiểm tra IP với IPHub
        if (isIpBlockedByIphub(ip)) {
            blockList.put(ip, currentTime);
            event.disallow(PlayerLoginEvent.Result.KICK_OTHER, ChatColor.RED + "Truy cập từ IP của bạn bị hạn chế.");
            logger.warning("IP bị hạn chế bởi IPHub: " + ip);
            return;
        }

        // Logic giới hạn tần suất
        if (isRateLimited(ip, currentTime)) {
            blockList.put(ip, currentTime);
            event.disallow(PlayerLoginEvent.Result.KICK_OTHER, ChatColor.RED + "Bạn đang bị giới hạn tần suất. Hãy thử lại sau.");
            logger.warning("IP bị giới hạn tần suất: " + ip);
            return;
        }

        // Kiểm tra kết nối đồng thời
        if (isConcurrentConnectionLimited(ip)) {
            event.disallow(PlayerLoginEvent.Result.KICK_OTHER, ChatColor.RED + "Quá nhiều kết nối đồng thời. Hãy thử lại sau.");
            logger.warning("Quá nhiều kết nối đồng thời từ IP: " + ip);
            return;
        }

        // Kiểm tra thời gian giữa các kết nối
        if (isConnectionTooFrequent(ip, currentTime)) {
            blockList.put(ip, currentTime);
            event.disallow(PlayerLoginEvent.Result.KICK_OTHER, ChatColor.RED + "Kết nối quá thường xuyên. Hãy thử lại sau.");
            logger.warning("Cố gắng kết nối quá thường xuyên từ IP: " + ip);
            return;
        }

        // Cho phép đăng nhập
        lastRequestTime.put(ip, currentTime);
        concurrentConnections.merge(ip, 1, Integer::sum);
        logger.info("IP " + ip + " đã được kết nối.");
    }

    private boolean isBlocked(String ip, long currentTime) {
        if (blockList.containsKey(ip)) {
            long blockTime = blockList.get(ip);
            if (currentTime - blockTime < blockTimeMs) {
                return true;
            } else {
                blockList.remove(ip);
            }
        }
        return false;
    }

    private boolean isRateLimited(String ip, long currentTime) {
        requestCounts.putIfAbsent(ip, 0);
        lastRequestTime.putIfAbsent(ip, 0L);

        long lastRequest = lastRequestTime.get(ip);
        if (currentTime - lastRequest > 60000) {
            requestCounts.put(ip, 0);
        }

        int requestCount = requestCounts.get(ip);
        if (requestCount >= maxRequestsPerMinute) {
            return true;
        } else {
            requestCounts.put(ip, requestCount + 1);
        }
        return false;
    }

    private boolean isConcurrentConnectionLimited(String ip) {
        int currentConnections = concurrentConnections.getOrDefault(ip, 0);
        return currentConnections >= maxConcurrentConnections;
    }

    private boolean isConnectionTooFrequent(String ip, long currentTime) {
        long lastRequest = lastRequestTime.getOrDefault(ip, 0L);
        return currentTime - lastRequest < minTimeBetweenConnectionsMs;
    }

    private boolean isIpBlockedByIphub(String ip) {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet("http://v2.api.iphub.info/ip/" + ip);
            request.setHeader("X-Key", iphubApiKey);

            HttpResponse response = httpClient.execute(request);
            String jsonResponse = EntityUtils.toString(response.getEntity());

            JSONObject jsonObject = new JSONObject(jsonResponse);
            int block = jsonObject.getInt("block");

            // block: 0 = residential, 1 = non-residential, 2 = non-residential and hosting provider
            return block > 0;
        } catch (IOException e) {
            logger.warning("Không thể kiểm tra IP với IPHub: " + e.getMessage());
        }
        return false;
    }

    private void startDdosProtectionMonitor() {
        Bukkit.getScheduler().runTaskTimer(this, () -> {
            // Kiểm tra các IP trong blockList và giảm thời gian block nếu thời gian đã hết
            long currentTime = System.currentTimeMillis();
            blockList.entrySet().removeIf(entry -> currentTime - entry.getValue() >= blockTimeMs);
        }, 20 * 60, 20 * 60); // Kiểm tra mỗi phút
    }
}
