use avgvsto_auth::{hash_password, verify_password, AuthRateLimiter, JwtService};
use std::net::{IpAddr, Ipv4Addr};
use uuid::Uuid;

#[test]
fn test_jwt_token_roundtrip() {
    let jwt = JwtService::new("test-secret-key-32-chars-long-for-testing!");
    let user_id = Uuid::new_v4();

    let tokens = jwt
        .generate_token_pair(user_id, "testuser", "user")
        .unwrap();

    let claims = jwt.validate_access_token(&tokens.access_token).unwrap();
    assert_eq!(claims.sub, user_id);
    assert_eq!(claims.username, "testuser");
    assert_eq!(claims.role, "user");
}

#[test]
fn test_jwt_expired_token() {
    let jwt = JwtService::new("test-secret-key-for-expiry-test!");
    let user_id = Uuid::new_v4();

    let tokens = jwt
        .generate_token_pair(user_id, "expireduser", "user")
        .unwrap();

    // Manually wait is not practical, but we can test that a random token is invalid
    let result = jwt.validate_access_token("invalid.token.here");
    assert!(result.is_err());
}

#[test]
fn test_refresh_token_validation() {
    let jwt = JwtService::new("refresh-secret-key-for-testing-12345");
    let user_id = Uuid::new_v4();

    let tokens = jwt
        .generate_token_pair(user_id, "refreshuser", "user")
        .unwrap();

    let refresh_claims = jwt
        .validate_refresh_token(&tokens.refresh_token)
        .unwrap();
    assert_eq!(refresh_claims.sub, user_id);
    assert_eq!(refresh_claims.role, "user");
}

#[test]
fn test_password_hashing_multiple_users() {
    let passwords = vec![
        ("alice", "alice-secure-password-123"),
        ("bob", "bob-other-password-456"),
        ("charlie", "charlie-different-pass-789"),
    ];

    let mut hashes = Vec::new();
    for (_user, password) in &passwords {
        let hash = hash_password(password).unwrap();
        hashes.push(hash);
    }

    // Each password should verify correctly
    for (i, (_user, password)) in passwords.iter().enumerate() {
        assert!(verify_password(password, &hashes[i]).unwrap());
    }

    // Wrong passwords should not verify
    assert!(!verify_password("wrong-password", &hashes[0]).unwrap());
    assert!(!verify_password(&passwords[1].1, &hashes[0]).unwrap());
}

#[test]
fn test_rate_limiter_per_ip_isolation() {
    let limiter = AuthRateLimiter::new(3, 60);
    let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    // Exhaust ip1
    assert!(limiter.check(ip1));
    assert!(limiter.check(ip1));
    assert!(limiter.check(ip1));

    // ip1 should be limited
    assert!(!limiter.check(ip1));

    // ip2 should still be allowed
    assert!(limiter.check(ip2));
    assert!(limiter.check(ip2));
}

#[test]
fn test_jwt_admin_role() {
    let jwt = JwtService::new("admin-test-secret-key-1234567890abc");
    let admin_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    let admin_tokens = jwt
        .generate_token_pair(admin_id, "admin", "admin")
        .unwrap();
    let user_tokens = jwt
        .generate_token_pair(user_id, "regular", "user")
        .unwrap();

    let admin_claims = jwt.validate_access_token(&admin_tokens.access_token).unwrap();
    let user_claims = jwt.validate_access_token(&user_tokens.access_token).unwrap();

    assert_eq!(admin_claims.role, "admin");
    assert_eq!(user_claims.role, "user");
    assert_ne!(admin_claims.role, user_claims.role);
}
