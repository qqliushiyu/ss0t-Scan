#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
爆破扫描核心模块
提供对常见服务的密码爆破功能
"""

import os
import time
import logging
import socket
import threading
from typing import Dict, List, Any, Optional, Union, Tuple, Callable
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import concurrent.futures

from core.base_scanner import BaseScanner, ScanResult

# 尝试导入支持的服务模块
try:
    import paramiko  # SSH
except ImportError:
    paramiko = None

try:
    import ftplib  # FTP
except ImportError:
    ftplib = None

try:
    import pymysql  # MySQL
except ImportError:
    pymysql = None

try:
    import pymongo  # MongoDB
except ImportError:
    pymongo = None

try:
    import redis  # Redis
except ImportError:
    redis = None

try:
    import telnetlib  # Telnet
except ImportError:
    telnetlib = None


class BruteforceScanner(BaseScanner):
    """爆破扫描器，用于对多种服务进行密码爆破"""
    
    VERSION = "1.0.0"
    
    # 支持的服务类型
    SUPPORTED_SERVICES = [
        {"id": "ssh", "name": "SSH", "default_port": 22, "available": paramiko is not None},
        {"id": "ftp", "name": "FTP", "default_port": 21, "available": ftplib is not None},
        {"id": "mysql", "name": "MySQL", "default_port": 3306, "available": pymysql is not None},
        {"id": "mongodb", "name": "MongoDB", "default_port": 27017, "available": pymongo is not None},
        {"id": "redis", "name": "Redis", "default_port": 6379, "available": redis is not None},
        {"id": "telnet", "name": "Telnet", "default_port": 23, "available": telnetlib is not None},
    ]
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        初始化爆破扫描器
        
        Args:
            config: 扫描器配置
        """
        super().__init__(config)
        self.logger = logging.getLogger("scanner.bruteforce_scan")
        
        # 扫描模式
        self.mode = self.config.get('mode', 'single')
        
        # 爆破扫描配置
        self.targets = self.config.get('targets', [])
        self.service_type = self.config.get('service_type', 'ssh')
        self.port = int(self.config.get('port', self._get_default_port(self.service_type)))
        self.username_list = self.config.get('username_list', [])
        self.password_list = self.config.get('password_list', [])
        self.username_file = self.config.get('username_file', '')
        self.password_file = self.config.get('password_file', '')
        self.threads = min(int(self.config.get('threads', 10)), 50)  # 限制最大线程数
        self.timeout = int(self.config.get('timeout', 3))
        self.stop_on_success = bool(self.config.get('stop_on_success', True))
        
        # 网段扫描特定配置
        self.service_detection = bool(self.config.get('service_detection', True))
        self.only_brute_open = bool(self.config.get('only_brute_open', True))
        
        # 扫描控制
        self.scan_started = False
        self.scan_stopped = False
        
        # 爆破结果
        self.results = []
        self._lock = threading.Lock()
    
    def _get_default_port(self, service_type: str) -> int:
        """获取服务的默认端口"""
        for service in self.SUPPORTED_SERVICES:
            if service["id"] == service_type:
                return service["default_port"]
        return 22  # 默认返回SSH端口
    
    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """验证扫描配置是否有效"""
        # 检查目标
        if not self.targets:
            return False, "请指定扫描目标"
        
        # 检查服务类型
        if self.service_type not in [s["id"] for s in self.SUPPORTED_SERVICES]:
            return False, f"不支持的服务类型: {self.service_type}"
        
        # 检查服务是否可用
        service_available = False
        for service in self.SUPPORTED_SERVICES:
            if service["id"] == self.service_type and service["available"]:
                service_available = True
                break
        
        if not service_available:
            return False, f"服务 {self.service_type} 所需的库未安装，请安装相应的依赖"
        
        # 检查用户名和密码列表
        if not self.username_list and not self.username_file:
            return False, "未提供用户名列表"
        
        if not self.password_list and not self.password_file:
            return False, "未提供密码列表"
        
        # 检查线程数
        if self.threads <= 0:
            return False, "线程数必须大于0"
        
        return True, None
    
    def _load_file_lines(self, file_path: str) -> List[str]:
        """从文件加载行数据"""
        if not file_path or not os.path.exists(file_path):
            return []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.logger.error(f"加载文件 {file_path} 失败: {str(e)}")
            return []
    
    def run_scan(self) -> ScanResult:
        """
        执行爆破扫描
        
        Returns:
            扫描结果对象
        """
        self.scan_started = True
        self.scan_stopped = False
        self.results = []
        
        # 初始化进度
        self.update_progress(5, "正在准备爆破扫描...")
        
        try:
            # 解析目标列表
            if isinstance(self.targets, str):
                targets = [t.strip() for t in self.targets.split(',') if t.strip()]
            elif isinstance(self.targets, list):
                targets = self.targets
            else:
                targets = []
            
            if not targets:
                return ScanResult(
                    success=False,
                    data=[],
                    error_msg="没有有效的扫描目标"
                )
            
            # 加载用户名和密码列表
            usernames = list(self.username_list)
            if self.username_file:
                usernames.extend(self._load_file_lines(self.username_file))
            
            passwords = list(self.password_list)
            if self.password_file:
                passwords.extend(self._load_file_lines(self.password_file))
            
            # 去重
            usernames = list(set(usernames))
            passwords = list(set(passwords))
            
            if not usernames:
                return ScanResult(
                    success=False,
                    data=[],
                    error_msg="没有有效的用户名"
                )
            
            if not passwords:
                return ScanResult(
                    success=False,
                    data=[],
                    error_msg="没有有效的密码"
                )

            # 检测目标是否有开放服务（网段扫描模式下）
            if self.mode == "network" and self.service_detection:
                self.update_progress(10, f"正在检测 {len(targets)} 个目标的服务开放状态...")
                targets = self._detect_open_services(targets)
                if not targets:
                    return ScanResult(
                        success=True,
                        data=[{
                            "check_type": "summary",
                            "message": "没有找到开放的服务",
                            "details": "扫描完成，未发现任何开放的服务。"
                        }],
                        error_msg=None
                    )
                
                self.update_progress(30, f"发现 {len(targets)} 个目标的服务开放，开始爆破...")
            
            self.logger.info(f"开始爆破扫描，共 {len(targets)} 个目标，{len(usernames)} 个用户名，{len(passwords)} 个密码")
            self.update_progress(40, f"开始爆破，共 {len(targets)} 个目标，{len(usernames)} 个用户名，{len(passwords)} 个密码...")
            
            # 使用线程池并发扫描
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # 提交所有扫描任务
                futures = []
                
                # 计算总任务数
                total_tasks = len(targets) * len(usernames) * len(passwords)
                completed_tasks = 0
                
                # 为每个目标创建爆破任务
                for target in targets:
                    if self.scan_stopped:
                        break
                    
                    # 创建目标状态记录
                    target_result = {
                        "target": target,
                        "service": self.service_type,
                        "port": self.port,
                        "status": "in_progress",
                        "credentials": [],
                        "start_time": time.time(),
                        "end_time": None
                    }
                    
                    with self._lock:
                        self.results.append(target_result)
                    
                    # 创建凭据组合并提交任务
                    for username in usernames:
                        for password in passwords:
                            if self.scan_stopped:
                                break
                            
                            futures.append(
                                executor.submit(
                                    self._try_credential,
                                    target,
                                    username,
                                    password,
                                    target_result
                                )
                            )
                
                # 等待所有任务完成
                for i, future in enumerate(concurrent.futures.as_completed(futures)):
                    if self.scan_stopped:
                        break
                    
                    completed_tasks += 1
                    progress = int(40 + (completed_tasks / total_tasks) * 60)
                    
                    self.update_progress(min(progress, 99), f"已完成 {completed_tasks}/{total_tasks} 个凭据组合")
            
            # 整理最终结果
            for result in self.results:
                result["end_time"] = time.time()
                
                if not result["credentials"]:
                    result["status"] = "failed"
                else:
                    result["status"] = "success"
            
            # 统计成功数
            success_count = sum(1 for r in self.results if r["status"] == "success")
            total_count = len(self.results)
            
            self.update_progress(100, f"爆破完成，成功 {success_count}/{total_count} 个目标")
            
            return ScanResult(
                success=True,
                data=self.results,
                error_msg=None
            )
        
        except Exception as e:
            error_msg = f"爆破扫描出错: {str(e)}"
            self.logger.error(error_msg)
            import traceback
            self.logger.debug(traceback.format_exc())
            
            return ScanResult(
                success=False,
                data=self.results if self.results else [],
                error_msg=error_msg
            )
    
    def _try_credential(self, 
                       target: str, 
                       username: str, 
                       password: str, 
                       target_result: Dict[str, Any]) -> bool:
        """
        尝试单个凭据
        
        Args:
            target: 目标主机
            username: 用户名
            password: 密码
            target_result: 目标结果字典的引用
        
        Returns:
            是否成功
        """
        if self.scan_stopped or (self.stop_on_success and target_result["credentials"]):
            return False
        
        try:
            # 根据服务类型调用不同的爆破方法
            success = False
            
            if self.service_type == "ssh":
                success = self._try_ssh(target, username, password)
            elif self.service_type == "ftp":
                success = self._try_ftp(target, username, password)
            elif self.service_type == "mysql":
                success = self._try_mysql(target, username, password)
            elif self.service_type == "mongodb":
                success = self._try_mongodb(target, username, password)
            elif self.service_type == "redis":
                success = self._try_redis(target, username, password)
            elif self.service_type == "telnet":
                success = self._try_telnet(target, username, password)
            
            # 如果成功，更新结果
            if success:
                with self._lock:
                    target_result["credentials"].append({
                        "username": username,
                        "password": password,
                        "time": time.time()
                    })
                    
                    # 记录日志
                    self.logger.info(f"找到凭据 - 目标: {target}, 服务: {self.service_type}, 用户名: {username}, 密码: {password}")
            
            return success
        
        except Exception as e:
            self.logger.debug(f"尝试凭据失败 - 目标: {target}, 用户名: {username}, 错误: {str(e)}")
            return False
    
    def _try_ssh(self, host: str, username: str, password: str) -> bool:
        """尝试SSH连接"""
        if not paramiko:
            return False
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            client.connect(
                hostname=host,
                port=self.port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )
            return True
        except (paramiko.AuthenticationException, paramiko.SSHException):
            return False
        except Exception:
            return False
        finally:
            client.close()
    
    def _try_ftp(self, host: str, username: str, password: str) -> bool:
        """尝试FTP连接"""
        if not ftplib:
            return False
        
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, self.port, self.timeout)
            ftp.login(username, password)
            ftp.quit()
            return True
        except ftplib.error_perm:
            return False
        except Exception:
            return False
    
    def _try_mysql(self, host: str, username: str, password: str) -> bool:
        """尝试MySQL连接"""
        if not pymysql:
            return False
        
        try:
            conn = pymysql.connect(
                host=host,
                port=self.port,
                user=username,
                password=password,
                connect_timeout=self.timeout
            )
            conn.close()
            return True
        except pymysql.Error:
            return False
        except Exception:
            return False
    
    def _try_mongodb(self, host: str, username: str, password: str) -> bool:
        """尝试MongoDB连接"""
        if not pymongo:
            return False
        
        try:
            uri = f"mongodb://{username}:{password}@{host}:{self.port}/?authSource=admin&connectTimeoutMS={self.timeout * 1000}"
            client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=self.timeout * 1000)
            client.server_info()  # 如果验证失败会抛出异常
            client.close()
            return True
        except pymongo.errors.PyMongoError:
            return False
        except Exception:
            return False
    
    def _try_redis(self, host: str, username: str, password: str) -> bool:
        """尝试Redis连接"""
        if not redis:
            return False
        
        try:
            r = redis.Redis(
                host=host,
                port=self.port,
                username=username if username else None,  # Redis 6.0+ 支持用户名
                password=password,
                socket_timeout=self.timeout,
                socket_connect_timeout=self.timeout
            )
            r.ping()
            r.close()
            return True
        except redis.RedisError:
            return False
        except Exception:
            return False
    
    def _try_telnet(self, host: str, username: str, password: str) -> bool:
        """尝试Telnet连接"""
        if not telnetlib:
            return False
        
        try:
            tn = telnetlib.Telnet(host, self.port, self.timeout)
            
            # 等待登录提示
            tn.read_until(b"login: ", self.timeout)
            tn.write(username.encode('ascii') + b"\n")
            
            # 等待密码提示
            tn.read_until(b"Password: ", self.timeout)
            tn.write(password.encode('ascii') + b"\n")
            
            # 检查是否登录成功
            response = tn.read_some()
            tn.close()
            
            # 如果返回内容中包含错误提示，则认为失败
            if b"incorrect" in response.lower() or b"failed" in response.lower() or b"denied" in response.lower():
                return False
            
            return True
        except Exception:
            return False
    
    def stop(self) -> None:
        """停止扫描"""
        if self.scan_started and not self.scan_stopped:
            self.logger.info("正在停止爆破扫描...")
            self.scan_stopped = True
            super().stop()
    
    @classmethod
    def get_supported_services(cls) -> List[Dict[str, Any]]:
        """获取支持的服务列表"""
        return cls.SUPPORTED_SERVICES 

    def _detect_open_services(self, targets: List[str]) -> List[str]:
        """
        检测目标列表中有哪些IP的服务是开放的
        
        Args:
            targets: 目标IP列表
            
        Returns:
            开放服务的IP列表
        """
        open_targets = []
        
        # 导入网络工具
        from utils.network import is_port_open
        
        # 使用线程池加速检测
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            
            for target in targets:
                futures[executor.submit(is_port_open, target, self.port, self.timeout)] = target
            
            # 处理结果
            total = len(futures)
            completed = 0
            
            for future in concurrent.futures.as_completed(futures):
                target = futures[future]
                completed += 1
                
                # 更新进度
                progress = int(10 + (completed / total) * 15)
                self.update_progress(progress, f"检测服务 {completed}/{total}: {target}:{self.port}")
                
                try:
                    is_open = future.result()
                    if is_open:
                        open_targets.append(target)
                        self.logger.info(f"目标 {target}:{self.port} 服务开放")
                except Exception as e:
                    self.logger.warning(f"检测目标 {target}:{self.port} 出错: {str(e)}")
        
        return open_targets 