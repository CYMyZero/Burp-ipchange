# Burp插件-ipchange
## ip动态切换

## 环境：java,python2,jython

## 此插件由于使用python开发需要安装jython环境(https://www.jython.org/download)

## python需要安装boto3模块

## 使用教程：
### file_path   填写代理文件路径
### 代理文件格式
### 127.0.0.1:8080
### 127.0.0.1:8081
### 每行一个ip

### sleep    请求延迟

### target host 直接使用单个http代理 （使用这个需要请空列表文件file_path）
### target protocol http代理类型
