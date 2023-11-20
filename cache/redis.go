package cache

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-redis/redis"
)

type RedisClient struct {
	client redis.Client
}

// NewRedisClient() creates a new redis client.
func NewRedisClient() *RedisClient {
	host := os.Getenv("REDIS_HOST")
	port := os.Getenv("REDIS_PORT")
	pass := os.Getenv("REDIS_PASS")
	fmt.Println(host + ":" + port)

	client := redis.NewClient(&redis.Options{
		Addr:     host + ":" + port,
		Password: pass,
		DB:       0,
	})

	redisClient := RedisClient{
		client: *client,
	}

	return &redisClient
}

// Get() gets a value from the redis server.
func (r *RedisClient) Get(ctx context.Context, key string) ([]byte, error) {
	res, err := r.client.Get(key).Result()
	if err != nil {
		return nil, nil
	}
	return []byte(res), nil
}

// Sets() sets a value into the redis server with given key and expiry time of 2 hours.
func (r *RedisClient) Set(ctx context.Context, key string, value string) error {
	_, err := r.client.Set(key, value, 2*time.Hour).Result()
	if err != nil {
		return err
	}
	return nil
}
