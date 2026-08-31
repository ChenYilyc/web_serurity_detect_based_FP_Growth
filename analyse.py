import streamlit as st
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
from itertools import combinations
from collections import defaultdict
from io import BytesIO

# --------------------------
# 数据预处理函数
# --------------------------
def make_baskets(df):
    df = df[['IPV4_SRC_ADDR', 'Attack', 'PROTOCOL', 'TCP_FLAGS']].dropna()
    df = df[df['Attack'] != 'Benign']
    df['item'] = df['Attack'] + '_P' + df['PROTOCOL'].astype(str) + '_F' + df['TCP_FLAGS'].astype(str)
    baskets = df.groupby('IPV4_SRC_ADDR')['item'].apply(lambda x: list(set(x))).tolist()
    return baskets

# --------------------------
# 自实现 FP-Tree 结构与频繁项集挖掘
# --------------------------
class FPNode:
    def __init__(self, item, parent):
        self.item = item
        self.count = 1
        self.parent = parent
        self.children = {}
        self.link = None

    def increment(self):
        self.count += 1

def build_fptree(transactions, min_support_count):
    header_table = {}
    for transaction in transactions:
        for item in transaction:
            header_table[item] = header_table.get(item, 0) + 1

    header_table = {item: count for item, count in header_table.items() if count >= min_support_count}
    if not header_table:
        return None, None

    for item in header_table:
        header_table[item] = [header_table[item], None]

    root = FPNode(None, None)

    for transaction in transactions:
        sorted_items = [item for item in transaction if item in header_table]
        sorted_items.sort(key=lambda i: (-header_table[i][0], str(i)))
        current_node = root
        for item in sorted_items:
            if item in current_node.children:
                current_node.children[item].increment()
            else:
                new_node = FPNode(item, current_node)
                current_node.children[item] = new_node
                if header_table[item][1] is None:
                    header_table[item][1] = new_node
                else:
                    link_node = header_table[item][1]
                    while link_node.link:
                        link_node = link_node.link
                    link_node.link = new_node
            current_node = current_node.children[item]

    return root, header_table

def ascend_fp_tree(node):
    path = []
    while node.parent and node.parent.item is not None:
        node = node.parent
        path.append(node.item)
    return path[::-1]

def find_prefix_paths(base_pat, node):
    cond_pats = []
    while node:
        path = ascend_fp_tree(node)
        if path:
            cond_pats.append((path, node.count))
        node = node.link
    return cond_pats

def mine_tree(header_table, min_support, prefix, freq_itemsets, total_transactions):
    sorted_items = sorted(header_table.items(), key=lambda i: i[1][0])
    for base_pat, (count, node) in sorted_items:
        new_freq_set = prefix.copy()
        new_freq_set.add(base_pat)
        freq_itemsets[frozenset(new_freq_set)] = count / total_transactions
        cond_pats = find_prefix_paths(base_pat, node)
        cond_transactions = []
        for path, path_count in cond_pats:
            for _ in range(path_count):
                cond_transactions.append(path)
        cond_tree, cond_header = build_fptree(cond_transactions, min_support)
        if cond_header:
            mine_tree(cond_header, min_support, new_freq_set, freq_itemsets, total_transactions)

def get_frequent_itemsets(transactions, min_support):
    min_support_count = int(min_support * len(transactions))
    tree, header = build_fptree(transactions, min_support_count)
    freq_itemsets = {}
    if header:
        mine_tree(header, min_support_count, set(), freq_itemsets, len(transactions))
    return freq_itemsets

# --------------------------
# 生成关联规则
# --------------------------
def generate_rules(freq_itemsets, min_conf):
    rules = []
    for itemset in freq_itemsets:
        if len(itemset) < 2:
            continue
        for i in range(1, len(itemset)):
            for antecedent in combinations(itemset, i):
                antecedent = frozenset(antecedent)
                consequent = itemset - antecedent
                if antecedent in freq_itemsets:
                    conf = freq_itemsets[itemset] / freq_itemsets[antecedent]
                    lift = conf / freq_itemsets[consequent] if consequent in freq_itemsets else 0
                    if conf >= min_conf:
                        rules.append({
                            'antecedents': antecedent,
                            'consequents': consequent,
                            'support': freq_itemsets[itemset],
                            'confidence': conf,
                            'lift': lift
                        })
    return rules

# --------------------------
# 页面设置
# --------------------------
st.set_page_config(page_title="网络攻击 FP-Growth 分析", layout="wide")
st.title("🔐 网络安全日志分析 - 关联规则挖掘")

uploaded_file = st.file_uploader("📁 上传网络日志 CSV 文件（推荐裁剪样本）", type=["csv"])

def init_session():
    if 'rules_sorted' not in st.session_state:
        st.session_state.rules_sorted = None
init_session()

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.success(f"✅ 成功加载数据，共 {len(df)} 条记录")
    st.dataframe(df.head())

    st.sidebar.title("⚙️ 分析参数")
    min_support = st.sidebar.slider("最小支持度", 0.01, 1.0, 0.05, 0.01)
    min_conf = st.sidebar.slider("最小置信度", 0.01, 1.0, 0.5, 0.01)

    if st.button("🚀 执行关联规则挖掘"):
        try:
            baskets = make_baskets(df)
            freq_itemsets = get_frequent_itemsets(baskets, min_support)
            rules = generate_rules(freq_itemsets, min_conf)

            if not rules:
                st.warning("⚠️ 没有发现满足条件的规则，请尝试调低参数或更换数据。")
            else:
                rules_df = pd.DataFrame(rules)
                rules_df['antecedents'] = rules_df['antecedents'].apply(lambda x: ', '.join(sorted(x)))
                rules_df['consequents'] = rules_df['consequents'].apply(lambda x: ', '.join(sorted(x)))
                rules_df = rules_df.sort_values(by="lift", ascending=False)
                st.session_state.rules_sorted = rules_df

                st.subheader("📊 提升度前 20 的关联规则")
                st.dataframe(rules_df.head(20), use_container_width=True)

                st.download_button(
                    "📥 下载完整规则 CSV",
                    rules_df.to_csv(index=False),
                    file_name="custom_fpgrowth_rules.csv",
                    mime="text/csv"
                )

                with st.expander("📌 可视化：攻击组合规则图谱（仅前 50 条规则）", expanded=False):
                    try:
                        G = nx.DiGraph()
                        for _, row in rules_df.head(50).iterrows():
                            ants = row['antecedents'].split(', ')
                            cons = row['consequents'].split(', ')
                            for ant in ants:
                                for con in cons:
                                    G.add_edge(ant, con, weight=row['lift'])

                        plt.figure(figsize=(12, 8))
                        pos = nx.spring_layout(G, k=0.5)
                        edges, weights = zip(*nx.get_edge_attributes(G, 'weight').items())
                        nx.draw(G, pos,
                                with_labels=True,
                                node_color='lightblue',
                                node_size=700,
                                edge_color=weights,
                                width=2,
                                edge_cmap=plt.cm.viridis)

                        buf = BytesIO()
                        plt.savefig(buf, format="png")
                        st.image(buf.getvalue(), caption="规则图谱可视化", use_container_width=True)
                    except Exception as e:
                        st.warning(f"⚠️ 可视化失败：{e}")

                def classify_threat(row):
                    if row['lift'] >= 3.5:
                        return "🔴 高风险"
                    elif row['lift'] >= 2.5:
                        return "🟠 中风险"
                    else:
                        return "🟢 低风险"

                rules_df['威胁等级'] = rules_df.apply(classify_threat, axis=1)

                with st.expander("🧮 规则威胁等级分级表", expanded=False):
                    st.dataframe(
                        rules_df[['antecedents', 'consequents', 'support', 'confidence', 'lift', '威胁等级']].head(20),
                        use_container_width=True
                    )

        except Exception as e:
            st.error(f"❌ 分析失败：{e}")

if st.session_state.rules_sorted is not None:
    with st.expander("🔍 攻击行为预测（输入某项攻击，查看其后续可能行为）"):
        search_term = st.text_input("请输入要查询的攻击项（如：Exploits_P6_F19）：")
        if search_term:
            filtered = st.session_state.rules_sorted[st.session_state.rules_sorted['antecedents'].str.contains(search_term)]
            if filtered.empty:
                st.warning("⚠️ 未找到包含该攻击项的规则。")
            else:
                st.write(f"📌 查询结果：以 `{search_term}` 为前件的规则（按置信度降序）")
                st.dataframe(
                    filtered.sort_values(by="confidence", ascending=False)[
                        ['antecedents', 'consequents', 'support', 'confidence', 'lift', '威胁等级']
                    ],
                    use_container_width=True
                )
