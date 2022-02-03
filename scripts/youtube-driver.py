import time
import sys
import os
import subprocess
import socket
from selenium import webdriver
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


def get_url(driver, url):
    print('Retrieving {}...'.format(url), end='')
    sys.stdout.flush()
    driver.delete_all_cookies()
    # Make sure DNS caches are fresh
    socket.getaddrinfo(url)
    start_time = time.time()
    driver.get(url)
    end_time = time.time()
    print('Done! {} s'.format((end_time - start_time)))


urls_with_ipv6 = ['google.com', 'youtube.com', 'facebook.com', 'yahoo.com',
                  'wikipedia.org', 'office.com', 'netflix.com',
                  'instagram.com', 'google.com.hk', 'bing.com',
                  'okezone.com', 'linkedin.com', 'yandex.ru', 'dropbox.com',
                  'mail.ru', 'google.co.in',
                  'whatsapp.com', 'google.com.br',
                  'canva.com', 'google.de', 'google.cn', 'spotify.com',
                  'espn.com', 'google.co.jp', 'telegram.org', 'bbc.com',
                  'cnn.com', 'google.ru', 'ilovepdf.com',
                  'pikiran-rakyat.com', 'google.fr', 'google.it',
                  'google.es', 't.me', 'dostor.org', 'google.com.sg',
                  'zerodha.com', 'indiatimes.com', 'speedtest.net',
                  'google.com.tw', 'youm7.com', 'bbc.co.uk', 'google.co.uk',
                  'aliyun.com', 'khtahmar.com', 'google.com.mx',
                  'google.com.tr', 'hdfcbank.com', 'suara.com', 'investing.com']

video_url = 'https://www.youtube.com/watch?v=sx3S-IciqkY'
result = subprocess.run(['uname', '-r'], stdout=subprocess.PIPE)
kernel_version = result.stdout.decode('utf-8').strip()

state_file_name = 'firefox-test-state_' + kernel_version
single_test = False
single_test_idx = 0

if len(sys.argv) > 1 and sys.argv[1] == '-s':
    single_test = True
    if not os.path.exists(state_file_name):
        with open(state_file_name, 'w+') as f:
            f.write(str(single_test_idx))
    else:
        with open(state_file_name, 'r') as f:
            single_test_idx = int(f.readline().strip())

options = webdriver.FirefoxOptions()
options.add_argument('-headless')
options.set_preference("browser.cache.disk.enable", False)
options.set_preference("browser.cache.memory.enable", False)
options.set_preference("browser.cache.offline.enable", False)
options.set_preference("network.http.use-cache", False)
options.set_preference("network.dns.disableIPv6", False)
driver = webdriver.Firefox(options=options)

if not single_test:
    print('Playing video...', end='')
    driver.delete_all_cookies()
    driver.get(video_url)
    element = WebDriverWait(driver, 15).until(EC.element_to_be_clickable(
        (By.XPATH, "//button[@aria-label='Play']")))
    start = time.time()
    ActionChains(driver).move_to_element(element).click().perform()
    while True:
        player_status = driver.execute_script(
            "return document.getElementById('movie_player').getPlayerState()")
        if player_status == 0:
            break
        time.sleep(1)
    end = time.time()
    print('Done! ({} s)'.format((end - start)))

    for url in urls_with_ipv6:
        get_url(driver, 'http://www.' + url)
else:
    url = urls_with_ipv6[single_test_idx]
    get_url(driver, 'http://www.' + url)
    with open(state_file_name, 'w') as f:
        f.write(str((single_test_idx + 1) % len(urls_with_ipv6)))

driver.close()
