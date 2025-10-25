// firewall.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/version.h>

// Прототип нашей хук-функции
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
static unsigned int firewall_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
#else
static unsigned int firewall_hook(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));
#endif

// Структура, описывающая наш хук
static struct nf_hook_ops firewall_ops;

// Переменные для хранения статистики
static unsigned long blocked_packets = 0;
static unsigned long total_packets = 0;

// Параметры модуля (можно менять при загрузке)
static unsigned int block_icmp = 1;
static unsigned int block_tcp_port = 8080;

module_param(block_icmp, uint, 0644);
MODULE_PARM_DESC(block_icmp, "Block ICMP Echo Requests (1 = enable, 0 = disable)");
module_param(block_tcp_port, uint, 0644);
MODULE_PARM_DESC(block_tcp_port, "TCP port to block (0 = disable blocking)");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
static unsigned int firewall_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
#else
static unsigned int firewall_hook(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
#endif
{
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    struct icmphdr *icmp_header;

    // Увеличиваем счетчик всех обработанных пакетов
    total_packets++;

    // Если skb или его data не инициализированы, пропускаем пакет
    if (!skb || !skb->data) {
        return NF_ACCEPT;
    }

    // Получаем IP-заголовок из skb
    ip_header = ip_hdr(skb);
    if (!ip_header) {
        return NF_ACCEPT;
    }

    // Анализируем протокол транспортного уровня
    switch (ip_header->protocol) {
        case IPPROTO_ICMP: // Это ICMP-пакет?
            if (block_icmp) {
                // Получаем указатель на ICMP-заголовок
                icmp_header = (struct icmphdr *)(skb->data + (ip_header->ihl * 4));
                if (!icmp_header) {
                    break;
                }

                // Проверяем, является ли пакет Echo Request (тип 8)
                if (icmp_header->type == ICMP_ECHO) {
                    // Увеличиваем счетчик и логируем блокировку
                    blocked_packets++;
                    printk(KERN_INFO "BLOCKED: ICMP Echo Request (ping) from %pI4 to %pI4\n",
                             &ip_header->saddr, &ip_header->daddr);
                    // Отбрасываем пакет
                    return NF_DROP;
                }
            }
            break;

        case IPPROTO_TCP: // Это TCP-пакет?
            if (block_tcp_port > 0) {
                // Получаем указатель на TCP-заголовок
                tcp_header = (struct tcphdr *)(skb->data + (ip_header->ihl * 4));
                if (!tcp_header) {
                    break;
                }

                // Проверяем, является ли порт назначения "запрещенным"
                if (ntohs(tcp_header->dest) == block_tcp_port) {
                    blocked_packets++;
                    printk(KERN_INFO "BLOCKED: TCP packet to port %d from %pI4:%u to %pI4:%u\n",
                             block_tcp_port,
                             &ip_header->saddr, ntohs(tcp_header->source),
                             &ip_header->daddr, ntohs(tcp_header->dest));
                    return NF_DROP;
                }
            }
            break;

        case IPPROTO_UDP: // Это UDP-пакет?
            // Можно добавить логику для UDP при необходимости
            break;

        // Для других протоколов просто выходим из switch
        default:
            break;
    }

    // Если пакет не подпадает под правила блокировки, пропускаем его
    return NF_ACCEPT;
}

static int __init firewall_init(void) {
    int ret;

    // Настраиваем структуру хука
    firewall_ops.hook = firewall_hook;
    firewall_ops.hooknum = NF_INET_LOCAL_OUT;
    firewall_ops.pf = PF_INET;
    firewall_ops.priority = NF_IP_PRI_FIRST;

    // Регистрируем хук в Netfilter (совместимый способ)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    ret = nf_register_net_hook(&init_net, &firewall_ops);
#else
    ret = nf_register_hook(&firewall_ops);
#endif

    if (ret < 0) {
        printk(KERN_ERR "Failed to register netfilter hook\n");
        return ret;
    }

    printk(KERN_INFO "Firewall module loaded successfully.\n");
    printk(KERN_INFO "Hook registered on NF_INET_LOCAL_OUT.\n");
    printk(KERN_INFO "Current rules:\n");
    printk(KERN_INFO "  - ICMP Echo Request blocking: %s\n", block_icmp ? "ENABLED" : "DISABLED");
    printk(KERN_INFO "  - TCP port blocking: %s\n", block_tcp_port > 0 ? "ENABLED" : "DISABLED");
    if (block_tcp_port > 0) {
        printk(KERN_INFO "  - Blocking TCP port: %d\n", block_tcp_port);
    }
    
    return 0;
}

static void __exit firewall_exit(void) {
    // Удаляем наш хук из Netfilter (совместимый способ)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_unregister_net_hook(&init_net, &firewall_ops);
#else
    nf_unregister_hook(&firewall_ops);
#endif

    // Выводим финальную статистику (без плавающей точки)
    printk(KERN_INFO "Firewall module unloaded.\n");
    printk(KERN_INFO "Statistics:\n");
    printk(KERN_INFO "  - Total packets processed: %lu\n", total_packets);
    printk(KERN_INFO "  - Total packets blocked: %lu\n", blocked_packets);
    
    // Вычисляем процент без использования float/double
    if (total_packets > 0) {
        unsigned long percent = (blocked_packets * 100) / total_packets;
        unsigned long remainder = ((blocked_packets * 100) % total_packets) * 100 / total_packets;
        printk(KERN_INFO "  - Block rate: %lu.%02lu%%\n", percent, remainder);
    }
}

module_init(firewall_init);
module_exit(firewall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Netfilter Firewall Developer");
MODULE_DESCRIPTION("A simple netfilter-based firewall module with ICMP and TCP port blocking");
MODULE_VERSION("1.0");
