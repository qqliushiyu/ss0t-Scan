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

try:
    import psycopg2  # PostgreSQL
except ImportError:
    psycopg2 = None

try:
    from smb.SMBConnection import SMBConnection  # SMB
except ImportError:
    SMBConnection = None


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
        {"id": "postgres", "name": "PostgreSQL", "default_port": 5432, "available": psycopg2 is not None},
        {"id": "smb", "name": "SMB", "default_port": 445, "available": SMBConnection is not None},
        {"id": "http-basic", "name": "HTTP基本认证", "default_port": 80, "available": True},
        {"id": "http-form", "name": "HTTP表单认证", "default_port": 80, "available": True},
    ]
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        初始化爆破扫描器
        
        Args:
            config: 扫描器配置
        """
        super().__init__(config)
        self.logger = logging.getLogger("scanner.bruteforce_scan")
        
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
        self.delay = float(self.config.get('delay', 0.1))  # 请求间延迟，防止触发防护
        
        # HTTP表单爆破的额外配置
        self.form_url = self.config.get('form_url', '')
        self.form_user_field = self.config.get('form_user_field', 'username')
        self.form_pass_field = self.config.get('form_pass_field', 'password')
        self.form_method = self.config.get('form_method', 'POST')
        self.form_success_match = self.config.get('form_success_match', '')
        self.form_failure_match = self.config.get('form_failure_match', '')
        
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
        
        # 对HTTP表单认证的特殊检查
        if self.service_type == 'http-form' and not self.form_url:
            return False, "使用HTTP表单认证时必须提供表单URL"
        
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
            
            self.logger.info(f"开始爆破扫描，共 {len(targets)} 个目标，{len(usernames)} 个用户名，{len(passwords)} 个密码")
            self.update_progress(10, f"开始爆破，共 {len(targets)} 个目标，{len(usernames)} 个用户名，{len(passwords)} 个密码...")
            
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
                
                # 处理扫描结果
                for future in futures:
                    if self.scan_stopped:
                        break
                    
                    try:
                        completed_tasks += 1
                        progress = int(10 + (85 * completed_tasks / total_tasks))
                        self.update_progress(
                            progress, 
                            f"已完成 {completed_tasks}/{total_tasks} 组凭据测试"
                        )
                        
                        _ = future.result()
                    except Exception as e:
                        self.logger.error(f"凭据测试出错: {str(e)}")
            
            # 更新所有目标的结束时间和状态
            for result in self.results:
                if result["status"] == "in_progress":
                    result["status"] = "completed"
                result["end_time"] = time.time()
            
            # 总结结果
            success_count = len([r for r in self.results if r["credentials"]])
            
            self.logger.info(f"爆破扫描完成，共发现 {success_count} 个目标的有效凭据")
            self.update_progress(100, f"爆破扫描完成，发现 {success_count} 个有效凭据")
            
            return ScanResult(
                success=True,
                data=self.results,
                metadata={
                    "scan_type": "bruteforce_scan",
                    "service_type": self.service_type,
                    "targets_count": len(targets),
                    "success_count": success_count
                }
            )
        
        except Exception as e:
            self.logger.error(f"执行爆破扫描时出错: {str(e)}", exc_info=True)
            return ScanResult(
                success=False,
                data=self.results,
                error_msg=f"爆破扫描出错: {str(e)}"
            )
        finally:
            self.scan_started = False
    
    def _try_credential(self, 
                       target: str, 
                       username: str, 
                       password: str, 
                       target_result: Dict[str, Any]) -> bool:
        """
        尝试一组凭据
        
        Args:
            target: 目标主机
            username: 用户名
            password: 密码
            target_result: 目标结果字典
            
        Returns:
            是否成功
        """
        # 如果已经成功爆破且配置为成功后停止，则跳过
        if self.stop_on_success and target_result.get("credentials"):
            return False
        
        try:
            # 根据服务类型调用对应的爆破方法
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
            elif self.service_type == "postgres":
                success = self._try_postgres(target, username, password)
            elif self.service_type == "smb":
                success = self._try_smb(target, username, password)
            elif self.service_type == "http-basic":
                success = self._try_http_basic(target, username, password)
            elif self.service_type == "http-form":
                success = self._try_http_form(target, username, password)
            
            # 如果凭据有效，记录到结果中
            if success:
                self.logger.info(f"发现有效凭据 - {target}:{self.port} - {username}:{password}")
                
                with self._lock:
                    target_result["credentials"].append({
                        "username": username,
                        "password": password,
                        "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                    })
            
            # 添加延迟，防止触发防护
            if self.delay > 0:
                time.sleep(self.delay)
            
            return success
            
        except Exception as e:
            self.logger.debug(f"尝试凭据 {username}:{password} 时出错: {str(e)}")
            return False
    
    def _try_ssh(self, host: str, username: str, password: str) -> bool:
        """尝试SSH登录"""
        if not paramiko:
            return False
        
        client = None
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=host,
                port=self.port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )
            
            # 验证连接是否正常工作
            _, stdout, _ = client.exec_command("echo success", timeout=self.timeout)
            output = stdout.read().decode('utf-8').strip()
            
            return output == "success"
        except (paramiko.AuthenticationException, paramiko.SSHException):
            # 认证失败，不是有效凭据
            return False
        except Exception as e:
            self.logger.debug(f"SSH连接错误 {host}:{self.port} - {str(e)}")
            return False
        finally:
            if client:
                client.close()
    
    def _try_ftp(self, host: str, username: str, password: str) -> bool:
        """尝试FTP登录"""
        if not ftplib:
            return False
        
        client = None
        try:
            client = ftplib.FTP()
            client.connect(host, self.port, timeout=self.timeout)
            client.login(username, password)
            
            # 验证连接是否能正常工作
            client.pwd()  # 获取当前目录
            
            return True
        except (ftplib.error_perm, ConnectionRefusedError):
            # 认证失败，不是有效凭据
            return False
        except Exception as e:
            self.logger.debug(f"FTP连接错误 {host}:{self.port} - {str(e)}")
            return False
        finally:
            if client:
                try:
                    client.quit()
                except:
                    pass
    
    def _try_mysql(self, host: str, username: str, password: str) -> bool:
        """尝试MySQL登录"""
        if not pymysql:
            return False
        
        conn = None
        try:
            conn = pymysql.connect(
                host=host,
                port=self.port,
                user=username,
                password=password,
                connect_timeout=self.timeout
            )
            
            # 验证连接是否能正常工作
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            
            return True
        except pymysql.Error:
            # 认证失败，不是有效凭据
            return False
        except Exception as e:
            self.logger.debug(f"MySQL连接错误 {host}:{self.port} - {str(e)}")
            return False
        finally:
            if conn:
                conn.close()
    
    def _try_mongodb(self, host: str, username: str, password: str) -> bool:
        """尝试MongoDB登录"""
        if not pymongo:
            return False
        
        client = None
        try:
            # 构建MongoDB连接URI
            if username and password:
                uri = f"mongodb://{username}:{password}@{host}:{self.port}/?authSource=admin"
            else:
                uri = f"mongodb://{host}:{self.port}/"
            
            client = pymongo.MongoClient(
                uri,
                serverSelectionTimeoutMS=self.timeout * 1000
            )
            
            # 验证连接是否正常工作
            client.admin.command('ismaster')
            
            return True
        except pymongo.errors.OperationFailure:
            # 认证失败，不是有效凭据
            return False
        except Exception as e:
            self.logger.debug(f"MongoDB连接错误 {host}:{self.port} - {str(e)}")
            return False
        finally:
            if client:
                client.close()
    
    def _try_redis(self, host: str, username: str, password: str) -> bool:
        """尝试Redis登录"""
        if not redis:
            return False
        
        client = None
        try:
            client = redis.Redis(
                host=host,
                port=self.port,
                password=password,
                socket_timeout=self.timeout,
                socket_connect_timeout=self.timeout
            )
            
            # 验证连接是否正常工作
            pong = client.ping()
            
            return pong
        except redis.exceptions.AuthenticationError:
            # 认证失败，不是有效凭据
            return False
        except Exception as e:
            self.logger.debug(f"Redis连接错误 {host}:{self.port} - {str(e)}")
            return False
        finally:
            if client:
                client.close()
    
    def _try_telnet(self, host: str, username: str, password: str) -> bool:
        """尝试Telnet登录"""
        if not telnetlib:
            return False
        
        tn = None
        try:
            tn = telnetlib.Telnet(host, self.port, timeout=self.timeout)
            
            # 等待登录提示
            tn.read_until(b"login: ", timeout=self.timeout)
            tn.write(username.encode('ascii') + b"\n")
            
            # 等待密码提示
            tn.read_until(b"Password: ", timeout=self.timeout)
            tn.write(password.encode('ascii') + b"\n")
            
            # 读取结果
            result = tn.read_some()
            
            # 检查是否登录成功（没有出现登录失败提示）
            if b"incorrect" not in result.lower() and b"failed" not in result.lower():
                return True
            
            return False
        except Exception as e:
            self.logger.debug(f"Telnet连接错误 {host}:{self.port} - {str(e)}")
            return False
        finally:
            if tn:
                tn.close()
    
    def _try_postgres(self, host: str, username: str, password: str) -> bool:
        """尝试PostgreSQL登录"""
        if not psycopg2:
            return False
        
        conn = None
        try:
            conn = psycopg2.connect(
                host=host,
                port=self.port,
                user=username,
                password=password,
                dbname="postgres",  # 尝试连接默认数据库
                connect_timeout=self.timeout
            )
            
            # 验证连接是否正常工作
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            
            return True
        except psycopg2.OperationalError:
            # 认证失败，不是有效凭据
            return False
        except Exception as e:
            self.logger.debug(f"PostgreSQL连接错误 {host}:{self.port} - {str(e)}")
            return False
        finally:
            if conn:
                conn.close()
    
    def _try_smb(self, host: str, username: str, password: str) -> bool:
        """尝试SMB登录"""
        if not SMBConnection:
            return False
        
        conn = None
        try:
            # 创建SMB连接
            conn = SMBConnection(
                username,
                password,
                "NetTools",  # 客户端名称
                host,  # 服务器名称
                use_ntlm_v2=True
            )
            
            # 尝试连接
            connected = conn.connect(host, self.port, timeout=self.timeout)
            
            # 如果连接成功，尝试列出共享
            if connected:
                shares = conn.listShares()
                return True
            
            return False
        except Exception as e:
            self.logger.debug(f"SMB连接错误 {host}:{self.port} - {str(e)}")
            return False
        finally:
            if conn and conn.sock:
                conn.close()
    
    def _try_http_basic(self, host: str, username: str, password: str) -> bool:
        """尝试HTTP基本认证"""
        import requests
        from requests.auth import HTTPBasicAuth
        
        try:
            # 构建完整URL
            if host.startswith(('http://', 'https://')):
                url = host
            else:
                url = f"http://{host}:{self.port}"
            
            # 发送带认证的请求
            response = requests.get(
                url,
                auth=HTTPBasicAuth(username, password),
                timeout=self.timeout,
                verify=False  # 忽略SSL证书验证
            )
            
            # 检查响应状态码
            return response.status_code != 401  # 401表示认证失败
        except Exception as e:
            self.logger.debug(f"HTTP基本认证错误 {host}:{self.port} - {str(e)}")
            return False
    
    def _try_http_form(self, host: str, username: str, password: str) -> bool:
        """尝试HTTP表单认证"""
        import requests
        
        try:
            # 使用配置中的表单URL，或根据目标构建URL
            if self.form_url:
                url = self.form_url
            elif host.startswith(('http://', 'https://')):
                url = host
            else:
                url = f"http://{host}:{self.port}"
            
            # 构建表单数据
            data = {
                self.form_user_field: username,
                self.form_pass_field: password
            }
            
            # 发送表单请求
            if self.form_method.upper() == "POST":
                response = requests.post(
                    url,
                    data=data,
                    timeout=self.timeout,
                    verify=False,  # 忽略SSL证书验证
                    allow_redirects=True
                )
            else:
                response = requests.get(
                    url,
                    params=data,
                    timeout=self.timeout,
                    verify=False,  # 忽略SSL证书验证
                    allow_redirects=True
                )
            
            # 根据配置的成功或失败标记判断结果
            if self.form_success_match and self.form_success_match in response.text:
                return True
            
            if self.form_failure_match and self.form_failure_match in response.text:
                return False
            
            # 如果没有配置匹配标记，则根据重定向和状态码判断
            # 通常登录成功会重定向到其他页面
            return "/login" not in response.url and response.status_code == 200
            
        except Exception as e:
            self.logger.debug(f"HTTP表单认证错误 {host}:{self.port} - {str(e)}")
            return False
    
    def stop(self) -> None:
        """停止扫描"""
        self.logger.info("停止爆破扫描")
        self.scan_stopped = True
    
    @classmethod
    def get_supported_services(cls) -> List[Dict[str, Any]]:
        """获取支持的服务列表"""
        return cls.SUPPORTED_SERVICES 