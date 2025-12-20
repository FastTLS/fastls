#!/usr/bin/env python3
"""
Fastls Fetch Python客户端示例
"""

import requests
from typing import Optional, Dict, Any


class FastlsFetchClient:
    """Fastls Fetch客户端"""
    
    def __init__(self, base_url: str = "http://localhost:8800"):
        """
        初始化Fetch客户端
        
        Args:
            base_url: Fetch服务器地址
        """
        self.base_url = base_url.rstrip('/')
        self.fetch_url = f"{self.base_url}/fetch"
    
    def health(self) -> Dict[str, str]:
        """健康检查"""
        response = requests.get(f"{self.base_url}/health")
        response.raise_for_status()
        return response.json()
    
    def fetch(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        proxy: Optional[str] = None,
        timeout: int = 30,
        disable_redirect: bool = False,
        user_agent: Optional[str] = None,
        fingerprint: Optional[Dict[str, str]] = None,
        browser: Optional[str] = None,
        cookies: Optional[list] = None
    ) -> Dict[str, Any]:
        """
        发送HTTP请求
        
        Args:
            url: 请求URL
            method: HTTP方法
            headers: 请求头
            body: 请求体
            proxy: 代理地址
            timeout: 超时时间（秒）
            disable_redirect: 是否禁用重定向
            user_agent: User-Agent
            fingerprint: 指纹配置 {"type": "ja3", "value": "..."} 或 {"type": "ja4r", "value": "..."}
            browser: 浏览器类型
            cookies: Cookie列表
            
        Returns:
            响应结果
        """
        payload = {
            "url": url,
            "method": method,
        }
        
        if headers:
            payload["headers"] = headers
        if body:
            payload["body"] = body
        if proxy:
            payload["proxy"] = proxy
        if timeout:
            payload["timeout"] = timeout
        if disable_redirect:
            payload["disableRedirect"] = disable_redirect
        if user_agent:
            payload["userAgent"] = user_agent
        if fingerprint:
            payload["fingerprint"] = fingerprint
        if browser:
            payload["browser"] = browser
        if cookies:
            payload["cookies"] = cookies
        
        response = requests.post(
            self.fetch_url,
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        return response.json()


def main():
    """示例用法"""
    # 创建客户端
    client = FastlsFetchClient("http://localhost:8800")
    
    # 1. 健康检查
    print("1. 健康检查:")
    health = client.health()
    print(f"   {health}\n")
    
    # 2. 简单GET请求
    print("2. 简单GET请求:")
    result = client.fetch("https://tls.peet.ws/api/all")
    print(f"   Status: {result['status']}")
    print(f"   OK: {result['ok']}")
    print(f"   Body length: {len(result['body'])} bytes\n")
    
    # 3. 使用浏览器指纹
    print("3. 使用Chrome142指纹:")
    result = client.fetch(
        "https://tls.peet.ws/api/all",
        browser="chrome142"
    )
    print(f"   Status: {result['status']}")
    print(f"   OK: {result['ok']}\n")
    
    # 4. 使用自定义JA3指纹
    print("4. 使用自定义JA3指纹:")
    result = client.fetch(
        "https://tls.peet.ws/api/all",
        fingerprint={
            "type": "ja3",
            "value": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
        }
    )
    print(f"   Status: {result['status']}")
    print(f"   OK: {result['ok']}\n")
    
    # 5. POST请求
    print("5. POST请求:")
    result = client.fetch(
        "https://httpbin.org/post",
        method="POST",
        headers={"Content-Type": "application/json"},
        body='{"key": "value"}'
    )
    print(f"   Status: {result['status']}")
    print(f"   OK: {result['ok']}\n")
    
    # 6. 带自定义请求头
    print("6. 带自定义请求头:")
    result = client.fetch(
        "https://httpbin.org/headers",
        headers={
            "X-Custom-Header": "custom-value",
            "Accept": "application/json"
        }
    )
    print(f"   Status: {result['status']}")
    print(f"   OK: {result['ok']}\n")


if __name__ == "__main__":
    main()

