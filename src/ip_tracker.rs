// src/ip_tracker.rs
// IP address tracking and limiting for users

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Трекер уникальных IP-адресов для каждого пользователя MTProxy
/// 
/// Предоставляет thread-safe механизм для:
/// - Отслеживания активных IP-адресов каждого пользователя
/// - Ограничения количества уникальных IP на пользователя
/// - Автоматической очистки при отключении клиентов
#[derive(Debug, Clone)]
pub struct UserIpTracker {
    /// Маппинг: Имя пользователя -> Множество активных IP-адресов
    active_ips: Arc<RwLock<HashMap<String, HashSet<IpAddr>>>>,
    
    /// Маппинг: Имя пользователя -> Максимально разрешенное количество уникальных IP
    max_ips: Arc<RwLock<HashMap<String, usize>>>,
}

impl UserIpTracker {
    /// Создать новый пустой трекер
    pub fn new() -> Self {
        Self {
            active_ips: Arc::new(RwLock::new(HashMap::new())),
            max_ips: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Установить лимит уникальных IP для конкретного пользователя
    /// 
    /// # Arguments
    /// * `username` - Имя пользователя
    /// * `max_ips` - Максимальное количество одновременно активных IP-адресов
    pub async fn set_user_limit(&self, username: &str, max_ips: usize) {
        let mut limits = self.max_ips.write().await;
        limits.insert(username.to_string(), max_ips);
    }

    /// Загрузить лимиты из конфигурации
    /// 
    /// # Arguments
    /// * `limits` - HashMap с лимитами из config.toml
    pub async fn load_limits(&self, limits: &HashMap<String, usize>) {
        let mut max_ips = self.max_ips.write().await;
        for (user, limit) in limits {
            max_ips.insert(user.clone(), *limit);
        }
    }

    /// Проверить, может ли пользователь подключиться с данного IP-адреса
    /// и добавить IP в список активных, если проверка успешна
    /// 
    /// # Arguments
    /// * `username` - Имя пользователя
    /// * `ip` - IP-адрес клиента
    /// 
    /// # Returns
    /// * `Ok(())` - Подключение разрешено, IP добавлен в активные
    /// * `Err(String)` - Подключение отклонено с описанием причины
    pub async fn check_and_add(&self, username: &str, ip: IpAddr) -> Result<(), String> {
        // Получаем лимит для пользователя
        let max_ips = self.max_ips.read().await;
        let limit = match max_ips.get(username) {
            Some(limit) => *limit,
            None => {
                // Если лимит не задан - разрешаем безлимитный доступ
                drop(max_ips);
                let mut active_ips = self.active_ips.write().await;
                let user_ips = active_ips
                    .entry(username.to_string())
                    .or_insert_with(HashSet::new);
                user_ips.insert(ip);
                return Ok(());
            }
        };
        drop(max_ips);

        // Проверяем и обновляем активные IP
        let mut active_ips = self.active_ips.write().await;
        let user_ips = active_ips
            .entry(username.to_string())
            .or_insert_with(HashSet::new);

        // Если IP уже есть в списке - это повторное подключение, разрешаем
        if user_ips.contains(&ip) {
            return Ok(());
        }

        // Проверяем, не превышен ли лимит
        if user_ips.len() >= limit {
            return Err(format!(
                "IP limit reached for user '{}': {}/{} unique IPs already connected",
                username,
                user_ips.len(),
                limit
            ));
        }

        // Лимит не превышен - добавляем новый IP
        user_ips.insert(ip);
        Ok(())
    }

    /// Удалить IP-адрес из списка активных при отключении клиента
    /// 
    /// # Arguments
    /// * `username` - Имя пользователя
    /// * `ip` - IP-адрес отключившегося клиента
    pub async fn remove_ip(&self, username: &str, ip: IpAddr) {
        let mut active_ips = self.active_ips.write().await;
        
        if let Some(user_ips) = active_ips.get_mut(username) {
            user_ips.remove(&ip);
            
            // Если у пользователя не осталось активных IP - удаляем запись
            // для экономии памяти
            if user_ips.is_empty() {
                active_ips.remove(username);
            }
        }
    }

    /// Получить текущее количество активных IP-адресов для пользователя
    /// 
    /// # Arguments
    /// * `username` - Имя пользователя
    /// 
    /// # Returns
    /// Количество уникальных активных IP-адресов
    pub async fn get_active_ip_count(&self, username: &str) -> usize {
        let active_ips = self.active_ips.read().await;
        active_ips
            .get(username)
            .map(|ips| ips.len())
            .unwrap_or(0)
    }

    /// Получить список всех активных IP-адресов для пользователя
    /// 
    /// # Arguments
    /// * `username` - Имя пользователя
    /// 
    /// # Returns
    /// Вектор с активными IP-адресами
    pub async fn get_active_ips(&self, username: &str) -> Vec<IpAddr> {
        let active_ips = self.active_ips.read().await;
        active_ips
            .get(username)
            .map(|ips| ips.iter().copied().collect())
            .unwrap_or_else(Vec::new)
    }

    /// Получить статистику по всем пользователям
    /// 
    /// # Returns
    /// Вектор кортежей: (имя_пользователя, количество_активных_IP, лимит)
    pub async fn get_stats(&self) -> Vec<(String, usize, usize)> {
        let active_ips = self.active_ips.read().await;
        let max_ips = self.max_ips.read().await;

        let mut stats = Vec::new();
        
        // Собираем статистику по пользователям с активными подключениями
        for (username, user_ips) in active_ips.iter() {
            let limit = max_ips.get(username).copied().unwrap_or(0);
            stats.push((username.clone(), user_ips.len(), limit));
        }
        
        stats.sort_by(|a, b| a.0.cmp(&b.0)); // Сортируем по имени пользователя
        stats
    }

    /// Очистить все активные IP для пользователя (при необходимости)
    /// 
    /// # Arguments
    /// * `username` - Имя пользователя
    pub async fn clear_user_ips(&self, username: &str) {
        let mut active_ips = self.active_ips.write().await;
        active_ips.remove(username);
    }

    /// Очистить всю статистику (использовать с осторожностью!)
    pub async fn clear_all(&self) {
        let mut active_ips = self.active_ips.write().await;
        active_ips.clear();
    }

    /// Проверить, подключен ли пользователь с данного IP
    /// 
    /// # Arguments
    /// * `username` - Имя пользователя
    /// * `ip` - IP-адрес для проверки
    /// 
    /// # Returns
    /// `true` если IP активен, `false` если нет
    pub async fn is_ip_active(&self, username: &str, ip: IpAddr) -> bool {
        let active_ips = self.active_ips.read().await;
        active_ips
            .get(username)
            .map(|ips| ips.contains(&ip))
            .unwrap_or(false)
    }

    /// Получить лимит для пользователя
    /// 
    /// # Arguments
    /// * `username` - Имя пользователя
    /// 
    /// # Returns
    /// Лимит IP-адресов или None, если лимит не установлен
    pub async fn get_user_limit(&self, username: &str) -> Option<usize> {
        let max_ips = self.max_ips.read().await;
        max_ips.get(username).copied()
    }

    /// Форматировать статистику в читаемый текст
    /// 
    /// # Returns
    /// Строка со статистикой для логов или мониторинга
    pub async fn format_stats(&self) -> String {
        let stats = self.get_stats().await;
        
        if stats.is_empty() {
            return String::from("No active users");
        }
        
        let mut output = String::from("User IP Statistics:\n");
        output.push_str("==================\n");
        
        for (username, active_count, limit) in stats {
            output.push_str(&format!(
                "User: {:<20} Active IPs: {}/{}\n",
                username,
                active_count,
                if limit > 0 { limit.to_string() } else { "unlimited".to_string() }
            ));
            
            let ips = self.get_active_ips(&username).await;
            for ip in ips {
                output.push_str(&format!("  └─ {}\n", ip));
            }
        }
        
        output
    }
}

impl Default for UserIpTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ТЕСТЫ
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn test_ipv4(oct1: u8, oct2: u8, oct3: u8, oct4: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(oct1, oct2, oct3, oct4))
    }

    fn test_ipv6() -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
    }

    #[tokio::test]
    async fn test_basic_ip_limit() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 2).await;

        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);
        let ip3 = test_ipv4(192, 168, 1, 3);

        // Первые два IP должны быть приняты
        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip2).await.is_ok());

        // Третий IP должен быть отклонен
        assert!(tracker.check_and_add("test_user", ip3).await.is_err());

        // Проверяем счетчик
        assert_eq!(tracker.get_active_ip_count("test_user").await, 2);
    }

    #[tokio::test]
    async fn test_reconnection_from_same_ip() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 2).await;

        let ip1 = test_ipv4(192, 168, 1, 1);

        // Первое подключение
        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        
        // Повторное подключение с того же IP должно пройти
        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        
        // Счетчик не должен увеличиться
        assert_eq!(tracker.get_active_ip_count("test_user").await, 1);
    }

    #[tokio::test]
    async fn test_ip_removal() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 2).await;

        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);
        let ip3 = test_ipv4(192, 168, 1, 3);

        // Добавляем два IP
        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip2).await.is_ok());
        
        // Третий не должен пройти
        assert!(tracker.check_and_add("test_user", ip3).await.is_err());

        // Удаляем первый IP
        tracker.remove_ip("test_user", ip1).await;
        
        // Теперь третий должен пройти
        assert!(tracker.check_and_add("test_user", ip3).await.is_ok());
        
        assert_eq!(tracker.get_active_ip_count("test_user").await, 2);
    }

    #[tokio::test]
    async fn test_no_limit() {
        let tracker = UserIpTracker::new();
        // Не устанавливаем лимит для test_user

        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);
        let ip3 = test_ipv4(192, 168, 1, 3);

        // Без лимита все IP должны проходить
        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip2).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip3).await.is_ok());
        
        assert_eq!(tracker.get_active_ip_count("test_user").await, 3);
    }

    #[tokio::test]
    async fn test_multiple_users() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("user1", 2).await;
        tracker.set_user_limit("user2", 1).await;

        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);

        // user1 может использовать 2 IP
        assert!(tracker.check_and_add("user1", ip1).await.is_ok());
        assert!(tracker.check_and_add("user1", ip2).await.is_ok());

        // user2 может использовать только 1 IP
        assert!(tracker.check_and_add("user2", ip1).await.is_ok());
        assert!(tracker.check_and_add("user2", ip2).await.is_err());
    }

    #[tokio::test]
    async fn test_ipv6_support() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 2).await;

        let ipv4 = test_ipv4(192, 168, 1, 1);
        let ipv6 = test_ipv6();

        // Должны работать оба типа адресов
        assert!(tracker.check_and_add("test_user", ipv4).await.is_ok());
        assert!(tracker.check_and_add("test_user", ipv6).await.is_ok());
        
        assert_eq!(tracker.get_active_ip_count("test_user").await, 2);
    }

    #[tokio::test]
    async fn test_get_active_ips() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 3).await;

        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);

        tracker.check_and_add("test_user", ip1).await.unwrap();
        tracker.check_and_add("test_user", ip2).await.unwrap();

        let active_ips = tracker.get_active_ips("test_user").await;
        assert_eq!(active_ips.len(), 2);
        assert!(active_ips.contains(&ip1));
        assert!(active_ips.contains(&ip2));
    }

    #[tokio::test]
    async fn test_stats() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("user1", 3).await;
        tracker.set_user_limit("user2", 2).await;

        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);

        tracker.check_and_add("user1", ip1).await.unwrap();
        tracker.check_and_add("user2", ip2).await.unwrap();

        let stats = tracker.get_stats().await;
        assert_eq!(stats.len(), 2);
        
        // Проверяем наличие обоих пользователей в статистике
        assert!(stats.iter().any(|(name, _, _)| name == "user1"));
        assert!(stats.iter().any(|(name, _, _)| name == "user2"));
    }

    #[tokio::test]
    async fn test_clear_user_ips() {
        let tracker = UserIpTracker::new();
        let ip1 = test_ipv4(192, 168, 1, 1);
        
        tracker.check_and_add("test_user", ip1).await.unwrap();
        assert_eq!(tracker.get_active_ip_count("test_user").await, 1);
        
        tracker.clear_user_ips("test_user").await;
        assert_eq!(tracker.get_active_ip_count("test_user").await, 0);
    }

    #[tokio::test]
    async fn test_is_ip_active() {
        let tracker = UserIpTracker::new();
        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);
        
        tracker.check_and_add("test_user", ip1).await.unwrap();
        
        assert!(tracker.is_ip_active("test_user", ip1).await);
        assert!(!tracker.is_ip_active("test_user", ip2).await);
    }

    #[tokio::test]
    async fn test_load_limits_from_config() {
        let tracker = UserIpTracker::new();
        
        let mut config_limits = HashMap::new();
        config_limits.insert("user1".to_string(), 5);
        config_limits.insert("user2".to_string(), 3);
        
        tracker.load_limits(&config_limits).await;
        
        assert_eq!(tracker.get_user_limit("user1").await, Some(5));
        assert_eq!(tracker.get_user_limit("user2").await, Some(3));
        assert_eq!(tracker.get_user_limit("user3").await, None);
    }
}
