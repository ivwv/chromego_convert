/*
 * Author: ivwv
 * Created: April 12, 2024
 * Description: A NodeJS script to Convert ChromeGo Proxies
 * Website: blog.ivwv.site
 * Email: ivwv@ivwv.site
 */

const yaml = require("js-yaml");
const fs = require("fs");
const geoip = require("geoip-lite");
const { promisify } = require("util");
const axios = require("axios");

const readFileAsync = promisify(fs.readFile);
const writeFileAsync = promisify(fs.writeFile);

let extractedProxies = [];
let serversList = [];

async function processUrls(urlsFile, processFunction) {
  try {
    const urls = fs
      .readFileSync(urlsFile, "utf8")
      .split("\n")
      .filter((url) => url.trim() !== "");

    for (let index = 0; index < urls.length; index++) {
      const url = urls[index];
      try {
        // const response = await axios.get(
        //   url.replace("raw.githubusercontent.com", "p.ivwv.site/raw.githubusercontent.com")
        // );
        const response = await axios.get(url);
        console.log(url);
        const data = response.data;
        await processFunction(data, index);
      } catch (error) {
        console.error(`处理 ${url} 时遇到错误: ${error}`);
      }
    }
  } catch (error) {
    console.error(`读取 ${urlsFile} 时遇到错误: ${error}`);
  }
}

async function processClashMeta(data, index) {
  try {
    const content = yaml.load(data);
    const proxies = content.proxies || [];
    for (let i = 0; i < proxies.length; i++) {
      const proxy = proxies[i];
      if (proxy.network === "ws") {
        if (
          `${proxy.server}:${proxy.port}-${proxy["ws-opts"]["headers"]["host"]}-ws` in serversList
        ) {
          continue;
        }
      } else if (`${proxy.server}:${proxy.port}-${proxy.type}` in serversList) {
        continue;
      }
      proxy.name = `${await getPhysicalLocation(proxy.server)}-${proxy.type} | ${index}-${i + 1}`;
      extractedProxies.push(proxy);
      serversList.push(`${proxy.server}:${proxy.port}-${proxy.type}`);
    }
  } catch (e) {
    console.error(`处理Clash Meta配置${index}时遇到错误: ${e}`);
  }
}

async function processHysteria(data, index) {
  try {
    const content = data;
    const auth = content.auth_str;
    const [server, ports] = content.server.split(":");
    const [serverPort, mport] = ports.split(",");
    const fastOpen = content.fast_open || true;
    const insecure = content.insecure;
    const sni = content.server_name;
    const location = await getPhysicalLocation(server);
    const name = `${location}-Hysteria | ${index}-0`;

    const proxy = {
      name,
      type: "hysteria",
      server,
      port: parseInt(serverPort),
      ports: parseInt(mport) || parseInt(serverPort),
      "auth-str": auth,
      up: 80,
      down: 100,
      "fast-open": fastOpen,
      protocol: content.protocol,
      sni,
      "skip-cert-verify": insecure,
      alpn: content.alpn ? [content.alpn] : [],
    };

    if (`${proxy.server}:${proxy.port}-hysteria` in serversList) {
      return;
    }
    extractedProxies.push(proxy);
    serversList.push(`${proxy.server}:${proxy.port}-hysteria`);
  } catch (e) {
    console.error(`处理Hysteria配置${index}时遇到错误: ${e}`);
  }
}
async function processHysteria2(data, index) {
  try {
    const content = data;
    const auth = content["auth"];
    const serverPortsSlt = content["server"].split(":");
    const server = serverPortsSlt[0];
    const ports = serverPortsSlt[1];
    const portsSlt = ports.split(",");
    const serverPort = parseInt(portsSlt[0]);
    const insecure = content["tls"]["insecure"];
    const sni = content["tls"]["sni"];
    const location = await getPhysicalLocation(server);
    const name = `${location}-Hysteria2 | ${index}-0`;

    const proxy = {
      name: name,
      type: "hysteria2",
      server: server,
      port: serverPort,
      password: auth,
      sni: sni,
      "skip-cert-verify": insecure,
    };

    if (!serversList.some((item) => item === `${proxy["server"]}:${proxy["port"]}-hysteria2`)) {
      extractedProxies.push(proxy);
      serversList.push(`${proxy["server"]}:${proxy["port"]}-hysteria2`);
    } else {
      return;
    }
  } catch (error) {
    console.error(`处理Hysteria2配置${index}时遇到错误: ${error}`);
    return;
  }
}

async function processXray(data, index) {
  try {
    const content = data;
    const outbounds = content["outbounds"];
    const pendingProxy = outbounds[0];
    const type = pendingProxy["protocol"];

    if (type === "vmess") {
      const server = pendingProxy["settings"]["vnext"][0]["address"];
      const port = pendingProxy["settings"]["vnext"][0]["port"];
      const uuid = pendingProxy["settings"]["vnext"][0]["users"][0]["id"];
      const alterId = pendingProxy["settings"]["vnext"][0]["users"][0]["alterId"];
      const cipher = pendingProxy["settings"]["vnext"][0]["users"][0]["security"];
      const network = pendingProxy["streamSettings"]["network"];
      const security = pendingProxy["streamSettings"]["security"] || "none";
      const location = await getPhysicalLocation(server);
      const name = `${location}-${type} | ${index}-0`;
      const tls = security !== "none";
      const sni = pendingProxy["streamSettings"]["tlsSettings"]
        ? pendingProxy["streamSettings"]["tlsSettings"]["serverName"]
        : "";
      const allowInsecure = pendingProxy["streamSettings"]["tlsSettings"]
        ? pendingProxy["streamSettings"]["tlsSettings"]["allowInsecure"]
        : false;

      let ws_path = "";
      let ws_headers = {};
      let grpc_serviceName = "";
      let h2_path = "";
      let h2_host = [];

      if (network === "tcp" || network === "ws" || network === "grpc" || network === "h2") {
        ws_path = pendingProxy["streamSettings"]["wsSettings"]
          ? pendingProxy["streamSettings"]["wsSettings"]["path"]
          : "";
        ws_headers = pendingProxy["streamSettings"]["wsSettings"]
          ? pendingProxy["streamSettings"]["wsSettings"]["headers"]
          : {};
        grpc_serviceName = pendingProxy["streamSettings"]["grpcSettings"]
          ? pendingProxy["streamSettings"]["grpcSettings"]["serviceName"]
          : "/";
        h2_path = pendingProxy["streamSettings"]["httpSettings"]
          ? pendingProxy["streamSettings"]["httpSettings"]["path"]
          : "/";
        h2_host = pendingProxy["streamSettings"]["httpSettings"]
          ? pendingProxy["streamSettings"]["httpSettings"]["host"]
          : [];
      } else {
        console.error(`处理Xray配置${index}时遇到错误: 不支持的VMess传输协议: ${network}`);
        return;
      }

      const proxy = {
        name: name,
        type: "vmess",
        server: server,
        port: port,
        uuid: uuid,
        alterId: alterId,
        cipher: cipher,
        tls: tls,
        servername: sni,
        "skip-cert-verify": allowInsecure,
        network: network,
        "ws-opts": {
          path: ws_path,
          headers: ws_headers,
        },
        "grpc-opts": {
          serviceName: grpc_serviceName,
        },
        "h2-opts": {
          path: h2_path,
          host: h2_host,
        },
      };

      if (!serversList.includes(`${proxy.server}:${proxy.port}-${proxy.type}`)) {
        extractedProxies.push(proxy);
        serversList.push(`${proxy.server}:${proxy.port}-${proxy.type}`);
      } else {
        return;
      }
    } else if (type === "vless") {
      const server = pendingProxy["settings"]["vnext"][0]["address"];
      const port = pendingProxy["settings"]["vnext"][0]["port"];
      const uuid = pendingProxy["settings"]["vnext"][0]["users"][0]["id"];
      const flow = pendingProxy["settings"]["vnext"][0]["users"][0]["flow"] || "";
      const security = pendingProxy["streamSettings"]["security"] || "none";
      const network = pendingProxy["streamSettings"]["network"];
      const location = await getPhysicalLocation(server);
      const name = `${location}-${type} | ${index}-0`;
      const tls = security !== "none";
      let sni = "";
      let fingerprint = "";
      let publicKey = "";
      let shortId = "";
      let grpc_serviceName = "";

      if (security === "reality") {
        const realitySettings = pendingProxy["streamSettings"]["realitySettings"] || {};
        sni = realitySettings["serverName"] || "";
        shortId = realitySettings["shortId"] || "";
        publicKey = realitySettings["publicKey"];
        fingerprint = realitySettings["fingerprint"];
        grpc_serviceName = pendingProxy["streamSettings"]["grpcSettings"]
          ? pendingProxy["streamSettings"]["grpcSettings"]["serviceName"]
          : "/";
      } else {
        if (network === "tcp" || network === "ws" || network === "grpc") {
          sni = pendingProxy["streamSettings"]["tlsSettings"]
            ? pendingProxy["streamSettings"]["tlsSettings"]["serverName"]
            : "";
          const allowInsecure = pendingProxy["streamSettings"]["tlsSettings"]
            ? pendingProxy["streamSettings"]["tlsSettings"]["allowInsecure"]
            : false;
          const ws_path = pendingProxy["streamSettings"]["wsSettings"]
            ? pendingProxy["streamSettings"]["wsSettings"]["path"]
            : "";
          const ws_headers = pendingProxy["streamSettings"]["wsSettings"]
            ? pendingProxy["streamSettings"]["wsSettings"]["headers"]
            : {};
          grpc_serviceName = pendingProxy["streamSettings"]["grpcSettings"]
            ? pendingProxy["streamSettings"]["grpcSettings"]["serviceName"]
            : "/";

          const proxy = {
            name: name,
            type: "vless",
            server: server,
            port: port,
            uuid: uuid,
            tls: tls,
            servername: sni,
            "skip-cert-verify": allowInsecure,
            network: network,
            "ws-opts": {
              path: ws_path,
              headers: ws_headers,
            },
            "grpc-opts": {
              serviceName: grpc_serviceName,
            },
          };

          if (!serversList.includes(`${proxy.server}:${proxy.port}-${proxy.type}`)) {
            extractedProxies.push(proxy);
            serversList.push(`${proxy.server}:${proxy.port}-${proxy.type}`);
          } else {
            return;
          }
        } else {
          console.error(`处理Xray配置${index}时遇到错误: 不支持的VLESS传输协议: ${network}`);
          return;
        }
      }

      const proxy = {
        name: name,
        type: "vless",
        server: server,
        port: port,
        uuid: uuid,
        flow: flow,
        tls: tls,
        servername: sni,
        network: network,
        "client-fingerprint": fingerprint,
        "grpc-opts": {
          "grpc-service-name": grpc_serviceName,
        },
        "reality-opts": {
          "public-key": publicKey,
          "short-id": shortId,
        },
      };

      if (!serversList.includes(`${proxy.server}:${proxy.port}-${proxy.type}`)) {
        extractedProxies.push(proxy);
        serversList.push(`${proxy.server}:${proxy.port}-${proxy.type}`);
      } else {
        return;
      }
    } else {
      console.error(`处理Xray配置${index}时遇到错误: 不支持的传输协议: ${type}`);
      return;
    }
  } catch (error) {
    console.error(`处理Xray配置${index}时遇到错误: ${error}`);
  }
}

async function getPhysicalLocation(address) {
  try {
    const geo = geoip.lookup(address);
    const country = geo ? geo.country : "CloudFlare";
    return `${country} ${getFlagEmoji(country)}`;
  } catch (e) {
    console.error(`区域代码获取失败: ${e}`);
    return "🏳 CloudFlare";
  }
}

function getFlagEmoji(countryCode) {
  // 将国家/地区代码转换为大写，以匹配 ISO 3166-1 alpha-2 格式
  const countryCodeUpper = countryCode.toUpperCase();

  // 计算国旗 emoji 的 Unicode 编码
  // 每个国家/地区的 Unicode 编码范围是从 'A' 到 'Z'，并且与国家/地区代码对应
  const unicodeOffset = 127397; // 国旗 emoji 的 Unicode 偏移量
  const firstLetter = countryCodeUpper.charCodeAt(0);
  const secondLetter = countryCodeUpper.charCodeAt(1);
  const emoji = String.fromCodePoint(firstLetter + unicodeOffset, secondLetter + unicodeOffset);

  return emoji;
}

async function writeClashMetaProfile(templateFile, outputFile, extractedProxies) {
  try {
    const template = await readFileAsync(templateFile, "utf-8");
    const profile = yaml.load(template);
    if (!profile.proxies || profile.proxies.length === 0) {
      profile.proxies = extractedProxies;
    } else {
      profile.proxies.push(...extractedProxies);
    }
    for (const group of profile["proxy-groups"]) {
      if (["🚀 节点选择", "♻️ 自动选择", "⚖ 负载均衡"].includes(group.name)) {
        if (!group.proxies || group.proxies.length === 0) {
          group.proxies = extractedProxies.map((proxy) => proxy.name);
        } else {
          group.proxies.push(...extractedProxies.map((proxy) => proxy.name));
        }
      }
    }
    await writeFileAsync(outputFile, yaml.dump(profile));
  } catch (e) {
    console.error(`写入${outputFile}时遇到错误: ${e}`);
  }
}

async function writeProxyUrlsFile(outputFile, proxies) {
  let proxyUrls = [];
  proxies.forEach((proxy) => {
    try {
      let proxyUrl;
      if (proxy.type === "vless") {
        let name = proxy.name;
        let server = proxy.server;
        let port = proxy.port;
        let uuid = proxy.uuid;
        let tls = parseInt(proxy.tls || 0);
        let network = proxy.network;
        let flow = proxy.flow || "";
        let grpcServiceName = proxy?.["grpc-opts"]?.["grpc-service-name"] || "";
        let wsPath = proxy?.["ws-opts"]?.["path"] || "";
        let wsHeadersHost =
          proxy?.["ws-opts"]?.["headers"]?.["host"] ||
          proxy?.["ws-opts"]?.["headers"]?.["Host"] ||
          "";

        let sni = proxy.servername || "";
        let publicKey = proxy?.["reality-opts"]?.["public-key"] || "";
        let shortId = proxy?.["reality-opts"]?.["short-id"] || "";
        let fingerprint = proxy["client-fingerprint"] || "";
        let insecure = proxy["skip-cert-verify"] ? 1 : 0;

        if (tls === 0) {
          proxyUrl = `vless://${uuid}@${server}:${port}?encryption=none&flow=${flow}&security=none&type=${network}&serviceName=${grpcServiceName}&host=${wsHeadersHost}&path=${wsPath}#${name}`;
        } else {
          if (publicKey !== "") {
            proxyUrl = `vless://${uuid}@${server}:${port}?encryption=none&flow=${flow}&security=reality&sni=${sni}&fp=${fingerprint}&pbk=${publicKey}&sid=${shortId}&type=${network}&serviceName=${grpcServiceName}&host=${wsHeadersHost}&path=${wsPath}#${name}`;
          } else {
            proxyUrl = `vless://${uuid}@${server}:${port}?encryption=none&flow=${flow}&security=tls&sni=${sni}&fp=${fingerprint}&insecure=${insecure}&type=${network}&serviceName=${grpcServiceName}&host=${wsHeadersHost}&path=${wsPath}#${name}`;
          }
        }
      } else if (proxy.type === "vmess") {
        let name = proxy.name;
        let server = proxy.server;
        let port = proxy.port;
        let uuid = proxy.uuid;
        let alterId = proxy.alterId;
        let tls = parseInt(proxy.tls || 0) === 1 ? "tls" : "";
        let sni = proxy.servername || "";
        let network = proxy.network;
        let type, path, host;
        if (network === "tcp") {
          type = "none";
          path = "";
          host = "";
        } else if (network === "ws") {
          type = "none";
          path = proxy?.["ws-opts"]?.path || "";
          host =
            proxy?.["ws-opts"]?.["headers"]?.host || proxy?.["ws-opts"]?.["headers"]?.Host || "";
        } else if (network === "grpc") {
          type = "gun";
          path = proxy?.["grpc-opts"]?.["grpc-service-name"] || "";
          host = "";
        } else if (network === "h2") {
          type = "none";
          path = proxy?.["h2-opts"]?.path || "";
          host = proxy?.["h2-opts"]?.["host"]?.join(",") || "";
        } else {
          return;
        }
        let vmessMeta = {
          v: "2",
          ps: name,
          add: server,
          port: port,
          id: uuid,
          aid: alterId,
          net: network,
          type: type,
          host: host,
          path: path,
          tls: tls,
          sni: sni,
          alpn: "",
        };
        vmessMeta = Buffer.from(JSON.stringify(vmessMeta)).toString("base64");
        proxyUrl = "vmess://" + vmessMeta;
      } else if (proxy.type === "ss") {
        let name = proxy.name;
        let server = proxy.server;
        let port = proxy.port;
        let password = proxy.password;
        let cipher = proxy.cipher;
        let ssMeta = Buffer.from(`${cipher}:${password}`).toString("base64");
        proxyUrl = `ss://${ssMeta}@${server}:${port}#${name}`;
      } else if (proxy.type === "hysteria") {
        let name = proxy.name;
        let server = proxy.server;
        let port = proxy.port;
        let protocol = proxy.protocol || "udp";
        let insecure = parseInt(proxy["skip-cert-verify"] || 0);
        let peer = proxy.sni || "";
        let auth = proxy["auth-str"] || proxy["auth_str"] || "";
        let upmbps = proxy.up || "11";
        let downmbps = proxy.down || "55";
        let alpn = (proxy.alpn || []).join(",");
        let obfs = proxy.obfs || "";
        proxyUrl = `hysteria://${server}:${port}/?protocol=${protocol}&insecure=${insecure}&peer=${peer}&auth=${auth}&upmbps=${upmbps}&downmbps=${downmbps}&alpn=${alpn}&obfs=${obfs}#${name}`;
      } else if (proxy.type === "hysteria2") {
        let name = proxy.name;
        let server = proxy.server;
        let port = proxy.port;
        let auth = proxy.password || "";
        let sni = proxy.sni || "";
        let insecure = parseInt(proxy["skip-cert-verify"] || 0);
        let obfs = proxy.obfs || "";
        let obfsPassword = proxy["obfs-password"] || "";
        if ("obfs" in proxy && proxy.obfs !== "") {
          proxyUrl = `hysteria2://${auth}@${server}:${port}/?sni=${sni}&insecure=${insecure}&obfs=${obfs}&obfs-password=${obfsPassword}#${name}`;
        } else {
          proxyUrl = `hysteria2://${auth}@${server}:${port}/?sni=${sni}&insecure=${insecure}#${name}`;
        }
      } else if (proxy.type === "tuic") {
        let name = proxy.name;
        let server = proxy.server;
        let port = proxy.port;
        let uuid = proxy.uuid;
        let password = proxy.password || "";
        let congestionController = proxy["congestion-controller"] || "bbr";
        let udpRelayMode = proxy["udp-relay-mode"] || "naive";
        let sni = proxy.sni || "";
        let alpn = (proxy.alpn || []).join(",");
        let allowInsecure = parseInt(proxy["skip-cert-verify"] || 1);
        let disableSni = parseInt(proxy["disable-sni"] || 0);
        proxyUrl = `tuic://${uuid}:${password}@${server}:${port}/?congestion_controller=${congestionController}&udp_relay_mode=${udpRelayMode}&sni=${sni}&alpn=${alpn}&allow_insecure=${allowInsecure}&disable_sni=${disableSni}#${name}`;
      } else {
        console.error(`处理 ${proxy.name} 时遇到问题: 不支持的协议: ${proxy.type}`);
        return;
      }

      proxyUrls.push(proxyUrl);
    } catch (error) {
      console.error(`处理 ${proxy.name} 时遇到问题: ${error}`);
      return;
    }
  });

  // 将 proxyUrls 写入 outputFile
  await fs.promises.writeFile(outputFile, proxyUrls.join("\n"), "utf-8");
}

async function writeBase64File(outputFile, proxyUrlsFile) {
  // 读取 proxyUrlsFile 文件中的内容
  const proxyUrls = fs.readFileSync(proxyUrlsFile, "utf-8");

  // 对代理 URL 进行编码
  // const encodedProxyUrls = encodeURIComponent(proxyUrls);

  // 将编码后的内容进行 Base64 编码
  const base64EncodedProxyUrls = Buffer.from(proxyUrls).toString("base64");

  // 将编码后的内容写入 outputFile
  fs.writeFileSync(outputFile, base64EncodedProxyUrls, "utf-8");
}

(async () => {
  // 处理clash meta urls
  await processUrls("./urls/clash_meta_urls.txt", processClashMeta);

  // // 处理hysteria urls
  await processUrls("./urls/hysteria_urls.txt", processHysteria);
  await processUrls("./urls/hysteria2_urls.txt", processHysteria2);

  // 处理xray urls
  await processUrls("./urls/xray_urls.txt", processXray);

  // 写入clash meta配置
  await writeClashMetaProfile(
    "./templates/clash_meta_warp.yaml",
    "./outputs/clash_meta_warp.yaml",
    extractedProxies
  );
  await writeClashMetaProfile(
    "./templates/clash_meta.yaml",
    "./outputs/clash_meta.yaml",
    extractedProxies
  );
  await writeProxyUrlsFile("./outputs/proxy-urls.txt", extractedProxies);

  // 写入base64文件
  await writeBase64File("./outputs/base64.txt", "./outputs/proxy-urls.txt");
  
})();
