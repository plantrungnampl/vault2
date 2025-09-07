package redis

import (
	"context"
	"fmt"
	"securevault/internal/config"
	"time"

	"github.com/redis/go-redis/v9"
)

// Client wraps the Redis client
type Client struct {
	client *redis.Client
	config *config.Config
}

// InitRedis initializes Redis client
func InitRedis(cfg *config.Config) (*Client, error) {
	redisURL := cfg.Redis.URL

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %v", err)
	}

	client := redis.NewClient(opt)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.Ping(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %v", err)
	}

	return &Client{
		client: client,
		config: cfg,
	}, nil
}

// Close closes the Redis connection
func (c *Client) Close() error {
	return c.client.Close()
}

// Del deletes a key from Redis
func (c *Client) Del(key string) error {
	ctx := context.Background()
	return c.client.Del(ctx, key).Err()
}

// Set sets a key-value pair in Redis
func (c *Client) Set(key, value string, expiration time.Duration) error {
	ctx := context.Background()
	return c.client.Set(ctx, key, value, expiration).Err()
}

// Get gets a value from Redis
func (c *Client) Get(key string) (string, error) {
	ctx := context.Background()
	return c.client.Get(ctx, key).Result()
}

// Exists checks if a key exists in Redis
func (c *Client) Exists(key string) (bool, error) {
	ctx := context.Background()
	result, err := c.client.Exists(ctx, key).Result()
	return result > 0, err
}

// SetNX sets a key only if it doesn't exist
func (c *Client) SetNX(key, value string, expiration time.Duration) (bool, error) {
	ctx := context.Background()
	return c.client.SetNX(ctx, key, value, expiration).Result()
}

// HSet sets a field in a hash
func (c *Client) HSet(key, field, value string) error {
	ctx := context.Background()
	return c.client.HSet(ctx, key, field, value).Err()
}

// HGet gets a field from a hash
func (c *Client) HGet(key, field string) (string, error) {
	ctx := context.Background()
	return c.client.HGet(ctx, key, field).Result()
}

// HGetAll gets all fields from a hash
func (c *Client) HGetAll(key string) (map[string]string, error) {
	ctx := context.Background()
	return c.client.HGetAll(ctx, key).Result()
}

// Incr increments a key
func (c *Client) Incr(key string) (int64, error) {
	ctx := context.Background()
	return c.client.Incr(ctx, key).Result()
}

// Expire sets an expiration on a key
func (c *Client) Expire(key string, expiration time.Duration) error {
	ctx := context.Background()
	return c.client.Expire(ctx, key, expiration).Err()
}

// ZAdd adds a member to a sorted set
func (c *Client) ZAdd(key string, score float64, member string) error {
	ctx := context.Background()
	return c.client.ZAdd(ctx, key, redis.Z{Score: score, Member: member}).Err()
}

// ZRangeByScore gets members by score range
func (c *Client) ZRangeByScore(key string, min, max float64) ([]string, error) {
	ctx := context.Background()
	return c.client.ZRangeByScore(ctx, key, &redis.ZRangeBy{
		Min: fmt.Sprintf("%f", min),
		Max: fmt.Sprintf("%f", max),
	}).Result()
}
