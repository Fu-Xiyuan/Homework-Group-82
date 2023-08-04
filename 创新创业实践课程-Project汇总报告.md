# 创新创业实践课程项目汇总

------

#### 组号：82

#### 姓名：付希远

#### 学号：202100460118

#### 班级：21级网安3班

------

[TOC]

------

### 1.整体完成情况

​		所有项目均由个人完成。除Project12部分完成外，其余均全部完成。下面会对每一个Project实现过程和结果做一个简单说明，详细实现在下面的“具体实现”中。所有代码都是在我的自己主机上运行，CPU型号为11th Gen Intel(R) Core(TM) i7-11800H @ 2.30GHz。

1. SM3的生日攻击。Python实现，67秒寻找到36比特碰撞。

2. SM3的Rho方法攻击。Python实现，297秒寻找到40比特碰撞。

3. SM3的长度扩展攻击。Python实现，完成一次用时约为1.02毫秒。

4. SM3实现的软件优化。所有版本均多次测试不同的数据大小计算平均用时。Python实现基础版SM3作为后续加速比较标准。利用语言速度不同加速，使用C++实现基础版SM3，加速比约为1.5。在C++基础上使用AVX2指令集进行SIMD优化，加速比约为10。最终实现加速比为10的SM3软件优化。

5. 依据RFC6962实现Merkle树。所以代码全都按照RFC6962实现。PPT中给定的三个条件，构建10w叶子节点树、给出特定元素的存在证明、给出特定元素的不存在证明，都已实现。

6. 在真实网络通信中实现年龄证明。证明过程是完全按照PPT中描述实现的。实现模拟真实网络通信，把我主机上的不同端口模拟为不同主机，端口间通信即为主机间通信。在通信过程中利用RSA-PKCS1_OAEP实现了加密传输。

7. 实现Generalizing Hash Chains。成功实现。流程全部按照PPT中图片展示流程实现。主要组件为KDF、PL-Accum、Shuffle、Padded Sparse MTree。

8. 使用ARM指令实现AES。我最终得到了ARM指令实现的AES。但是不是自己使用ARM指令写出来的，是首先用C实现了AES然后在Ubuntu下使用arm-linux-gnueabi-gcc进行交叉编译，用ARM架构中的指令集编译出C得到ARM架构下的指令集。

9. AES和SM4的软件实现。实现了Python和C版本的AES以及C版本的SM4。实现全都参照官方文档。

10. ECDSA从签名技术推导公钥在以太坊应用情况研究报告。通过网络搜索资料编写。

11. 依据RFC6979实现SM2。Python实现。RFC6979给出的是确定性（EC）DSA签名算法的实现，主要内容为确定性k值的生成，成功实现。

12. 验证签名陷阱。Python实现。PPT中给出了ECDSA、Schnorr和SM2-sign的七种陷阱。我只代码验证了ECDSA中的三种缺陷，包括泄露k导致泄露d，重用k导致泄露d以及k和d相同导致泄露d。

13. 实现ECMH协议。Python实现。完成了ECMH的基本功能。

14. 使用SM2实现PGP协议。Python实现。流程完全按照标准PGP协议，成功实现。

15. 真实网络通信中实现SM2 2P签名。Python实现。签名流程全部按照PPT中给出的流程实现。

16. 真实网络通行中实现SM2 2p解密。Python实现。解密流程全部按照PPT中给出的流程实现。

17. 比较火狐和谷歌记住密码插件的实现区别。首先是通过使用观察一些基础实现区别。之后查看各自源码寻找具体实现区别。

18. 在比特币测试网上发送一笔交易然后逐比特解析交易数据。发送交易我是利用的Bitcoin Core软件进行的。解析数据是利用解析网站进行的。

19. 伪造中本聪签名。Python实现。实现参考了网络帖子，帖子链接在下面详细实现中。

20. Schnorr Batch。Python实现。批量验证成功实现。

21. Merkle Patricia Tree（MPT）研究报告。通过网络搜索资料编写。

    

    

### 2.具体实现

#### 2.1 - implement the naïve birthday attack of reduced SM3

1. 原理

   生日攻击是基于概率论中的生日问题实现的。所谓生日问题，就是一个班级需要有多少人，才能保证每个同学的生日都不一样？，每个同学生日都不一样的反事件就是存在两个同学生日一样，放在SM3等hash函数中就是碰撞的概念。因此，基于生日问题计算出的概率公式可以推导出计算出某种碰撞出现概率大于某个值所需要的穷举空间。将生日问题中的365一般化为穷举空间d，可以得到hash碰撞的概率公式，为
   $$
   p(n,d) = 1 - e^{-\frac{n(n-1)}{2d}}
   $$
   一般来说，当输出长度为n比特时，必须至少有$2^\frac{n}{2}$个不同输入才能保证产生碰撞的概率大于50%。

2. 实现

   随机生成消息，计算出对应的hash值并查看表中是否存在该hash值，如果存在那么碰撞找到就结束遍历，如果不存在就将该值存入表中继续遍历，直到找到碰撞结束。关键代码如下：

   ```python
   def birthday_attack():
       # 创建一个字典，存储对应的消息和hash值
       hash_table = {}
       while True:
           # 随机生成消息
           message = generate_message()
           # 计算对应的hash值
           hash_value = calculate_hash(message)
           # 如果该hash值存在且对应消息值不同，那么碰撞找到，结束
           if hash_value in hash_table and message != hash_table[hash_value]:
               return message, hash_table[hash_value], hash_value
           else:
               hash_table[hash_value] = message
   ```

   但是SM3的输出结果为256比特，想要通过生日攻击寻找到碰撞，是不现实的，所以只能寻找部分碰撞，也就是输出的部分比特的碰撞，关键代码如下：

   ```python
   def birthday_attack():
       # 创建一个字典，存储对应的消息和hash值
       hash_table = {}
       attack_size = [1, 2, 4, 8, 9]
       for i in range(len(attack_size)):
           stat_time = time.time()
           while True:
               # 随机生成消息
               message = secrets.token_hex(16)
               # 计算对应的hash值
               same_value = SM3.sm3(message)[:attack_size[i]]
               # 如果该hash值存在且对应消息值不同，那么碰撞找到，结束
               if same_value in hash_table and message != hash_table[same_value]:
                   end_time = time.time()
                   use_time = end_time - stat_time
                   print("Message 1:", message, "Hash Value :", SM3.sm3(message))
                   print("Message 2:", hash_table[same_value], "Hash Value :", SM3.sm3(hash_table[same_value]))
                   print("Same Value :", same_value)
                   print("Same Value Size :", attack_size[i]*4, "bits")
                   print("Time Use :", use_time)
                   print("--------------------------------------------------------------------")
                   break
               else:
                   hash_table[same_value] = message
   ```

   我选取了五组碰撞大小，分别为4,8,16,32和36比特，测试结果为：

   | 碰撞大小（bits） | 4       | 8       | 16      | 32      | 36       |
   | ---------------- | ------- | ------- | ------- | ------- | -------- |
   | 寻找时间（s）    | 0.00205 | 0.00321 | 0.10871 | 10.9041 | 67.11287 |

   

   ![](D:\Desktop\创新创业实践\project1\Snipaste_2023-07-20_17-56-31.png)

3. 实现环境

   CPU:

   ![](D:\Desktop\创新创业实践\project1\Snipaste_2023-07-20_19-25-05.png)

   软件:

   PyCharm Community Edition 2023.1.4

   
   
   



#### 2.2 - implement the Rho method of reduced SM3

1. 原理

   ![](D:\Desktop\创新创业实践\project2\Snipaste_2023-07-20_21-31-01.png)

   原理图如上所示，基本思想是通过不断迭代更新hash值，很可能会形成环状结构，如上图中$H_4$和$H_{10}$的Hash值是相同的，也就找到了碰撞。

2. 实现

   ```python
   def rho_method_test():
       attack_size = [1, 2, 4, 8, 9, 10]
       for i in range(len(attack_size)):
           stat_time = time.time()
           # 创建一个字典，存储对应的消息和hash值
           hash_table = {}
           # 随机生成消息
           message = secrets.token_hex(16)
           while True:
               # 计算对应的hash值
               hash_value = SM3.sm3(message)
               same_value = hash_value[:attack_size[i]]
               # 如果该hash值存在且对应消息值不同，那么碰撞找到，结束
               if same_value in hash_table and message != hash_table[same_value]:
                   end_time = time.time()
                   use_time = end_time - stat_time
                   print("Message 1:", message, "Hash Value :", SM3.sm3(message))
                   print("Message 2:", hash_table[same_value], "Hash Value :", SM3.sm3(hash_table[same_value]))
                   print("Same Value :", same_value)
                   print("Same Value Size :", attack_size[i]*4, "bits")
                   print("Time Use :", use_time)
                   print("--------------------------------------------------------------------")
                   break
               else:
                   hash_table[same_value] = message
                   message = hash_value
   ```

   选取了6种碰撞情况，分别为4,8,16,32,36和40比特，具体时间为：

   | 碰撞大小（bits） | 4       | 8       | 16      | 32       | 36       | 40        |
   | ---------------- | ------- | ------- | ------- | -------- | -------- | --------- |
   | 寻找时间（s）    | 0.00609 | 0.00901 | 0.17289 | 33.11247 | 93.90767 | 296.79887 |

   ![](D:\Desktop\创新创业实践\project2\Snipaste_2023-07-20_22-35-50.png)

3. 环境

   CPU:

   ![](D:\Desktop\创新创业实践\project2\Snipaste_2023-07-20_22-43-35.png)

   软件:

   PyCharm Community Edition 2023.1.4

   



#### 2.3 - implement length extension attack for SM3, SHA256, etc.

1. 原理

   长度扩展攻击是一种针对哈希函数的攻击方式，攻击者在获得消息和对应的Hash值后，通过长度扩展攻击来构造另一个消息和对应的Hash值。可以进行该攻击的哈希函数需要满足两个条件，第一个是加密前要将明文按一定规则填充到固定长度的整数倍，第二个是加密过程中用前一块明文的密文作为后一块明文加密的初始向量。下面以SM3加密算法为例阐述长度扩展攻击的原理。

   ![](D:\Desktop\创新创业实践\project3\Snipaste_2023-07-23_09-19-50.png)

   上图为SM3加密的主体结构，每一块明文$B_i$都和对应的初始向量$V_i$进行压缩函数$CF$运算，之后将结果更新到初始向量表中参与下次运算。假设我们现在有明文$m$和对应的Hash值$H$，根据SM3的加密流程，首先会对$m$进行填充，假设为$m'$，然后进行上图的压缩运算，最后得到$H$。根据对每一块的运算过程，可以发现，如果此时$m'$的后面还有一组明文$B'$，那么对这一块进行压缩运算时，对应的$V'$就是我们之前的$H$，然后运算结果就是新的Hash值。这时候，我们已经知道进过填充后的明文以及对应的Hash值，就可以根据填充规则倒推出填充前的明文，这样就构造出了一对匹配的（明文，SM3（明文）），攻击成功。

2. 实现

   长度扩展攻击的原理如上所示，以下为实现的主要步骤。首先处理已知哈希值作为最后一轮压缩的向量值。之后随机构造一个添加的消息并计算出对应的伪造消息。然后根据伪造消息确定增加的最后一个分组的值。接着就直接进行压缩函数运算就可以了，最后需要转换一下压缩结果的格式。实现过程中参数格式要求不同，需要不断进行转换。但其中的组件都可以从SM3算法中直接摘取组合。

   ```python
   def len_ex_attach(message, hash_message):
       # 处理已知哈希值作为初始向量
       iv = int(hash_message, 16)
       a = []
       for i in range(0, 8):
           a.append(0)
           a[i] = (iv >> ((7 - i) * 32)) & 0xFFFFFFFF
       iv = a
       # 随机选取一个添加消息
       salt = secrets.token_hex(16)
       # 根据已知消息和添加消息构造攻击消息
       salt1 = byte2hex(padding(hex2byte(message))) + salt
       # 根据攻击消息确定最后一个分组的值
       salt2 = deal(padding(hex2byte(salt1)))
       index = len(salt1) // 128
       # 利用已知哈希值作为初始向量，与构造出的最后一个分组作压缩运算得到构造的
       attach = SM3.CF(iv, salt2[index])
       # 将得到的字节数组转换为十六进制字符串，保证八位转换防止删除高位0
       result = ""
       for i in attach:
           result = '%s%08x' % (result, i)
       # 返回构造出的消息和哈希值
       return salt1, result
   ```

   

   运行测试

   代码：

   ```python
   def run_test():
       message = secrets.token_hex(16)
       hash_message = SM3.sm3(message)
       message_, hash_message_ = len_ex_attach(message, hash_message)
       Hash = SM3.sm3(message_)
       if hash_message_ == Hash:
           print("Length Extension Attach Success !")
           print("已知的消息、哈希值")
           print("Message 1:", message, "\nHash Value :", hash_message)
           print("构造的消息、哈希值")
           print("Message 2:", message_, "\nHash Value :", hash_message_)
       else:
           print("Length Extension Attach Fail !")
   ```

   结果：

   ![](D:\Desktop\创新创业实践\project3\Snipaste_2023-07-23_10-55-21.png)

   

   开销测试

   代码：

   ```python
   def time_test():
       flag = 0
       start_time = time.time()
       for i in range(1000):
           message = secrets.token_hex(16)
           hash_message = SM3.sm3(message)
   
           message_, hash_message_ = len_ex_attach(message, hash_message)
   
           Hash = SM3.sm3(message_)
           if hash_message_ == Hash:
               flag += 1
           else:
               flag = 0
       end_time = time.time()
       average = (end_time - start_time) / 1000
       if flag == 1000:
           print('全部成功')
           print("平均消耗时间 :", average)
       else:
           print("出现错误")
   ```

   结果：平均一次时间为0.00102秒

   ![](D:\Desktop\创新创业实践\project3\Snipaste_2023-07-23_11-05-51.png)

3. 环境

   CPU:

   ![](D:\Desktop\创新创业实践\project2\Snipaste_2023-07-20_22-43-35.png)

   软件:

   PyCharm Community Edition 2023.1.4



#### 2.4 - do your best to optimize SM3 implementation (software)

1. 实现

   第一个和第二个基础实现就是根据国家密码管理局2010年12月发布的《SM3密码杂凑算法》文档完成的，流程及算法均为文档复现，没有额外加入任何优化。第三个是利用了AVX2指令集进行了计算的优化加速。

   

   1. Python 基础实现

      首先是利用Python语言实现的SM3算法，具体代码放在了project4文件夹中了，其他使用SM3的项目中也均有该实现。

      

      效果测试

      代码：

      ```python
      def test():
          data_size = [1024 * 1024, 1024 * 1024 * 32, 1024 * 1024 * 64, 1024 * 1024 * 128, 1024 * 1024 * 256]
          for j in range(5):
              data = gen_random_string(data_size[j])
              start_time = time.time()
              sm3(data, 0)
              end_time = time.time()
              use_time = end_time - start_time
              print("加密 {} 数据 1 次用时为 :{} 秒".format(data_size[j], use_time / 10))
      ```

      结果：

      ![](D:\Desktop\创新创业实践\project4\Snipaste_2023-07-25_09-18-53.png)

      | 数据大小 | 1MB     | 32MB     | 64MB     | 128MB    | 256MB     |
      | -------- | ------- | -------- | -------- | -------- | --------- |
      | 平均用时 | 0.3987s | 13.7352s | 25.4156s | 54.1977s | 102.1415s |

      

   2. C++ 基础实现

      具体代码放入project4文件夹下了。

      

      效果测试

      代码：

      ```c++
      int main() 
      {
          int data_size[5] = {1024 * 1024, 1024 * 1024 * 32, 1024 * 1024 * 64, 1024 * 1024 * 128, 1024 * 1024 * 256};
          for (int j = 0;j < 5;j++)
          {
              string message = generateRandomString(data_size[j]);
              string digest;
              auto start = std::chrono::high_resolution_clock::now();
              for (int i = 0;i < 10;i++)
              {
                  SM3(message, digest);
              }
              auto end = std::chrono::high_resolution_clock::now();
              auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
              cout << "加密 "<< data_size[j] <<" 字节数据 10 次的总用时为 " << duration << " 毫秒" << endl;
              cout << "加密 " << data_size[j] << " 字节数据 1 次的平均用时为 " << duration / 10 << " 毫秒" << endl;
          }
          return 0;
      }
      ```

      结果：

      ![](D:\Desktop\创新创业实践\project4\Snipaste_2023-07-25_00-28-26.png)

      | 数据大小 | 1MB  | 32MB   | 64MB   | 128MB  | 256MB   |
      | -------- | ---- | ------ | ------ | ------ | ------- |
      | 平均用时 | 56ms | 1881ms | 3948ms | 7839ms | 15630ms |

      

   3. 利用AVX2指令集优化

      效果测试

      代码：

      ```c++
      int main()
      {
          int data_size[5] = { 1024 * 1024, 1024 * 1024 * 32, 1024 * 1024 * 64, 1024 * 1024 * 128, 1024 * 1024 * 256 };
          for (int j = 0;j < 5;j++)
          {
              string message = generateRandomString(data_size[j]);
              string digest;
              auto start = std::chrono::high_resolution_clock::now();
              for (int i = 0;i < 10;i++)
              {
                  SM3_AVX2(message, digest);
              }
              auto end = std::chrono::high_resolution_clock::now();
              auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
              cout << "加密 " << data_size[j] << " 字节数据 10 次的总用时为 " << duration << " 毫秒" << endl;
              cout << "加密 " << data_size[j] << " 字节数据 1 次的平均用时为 " << duration / 10 << " 毫秒" << endl;
          }
          return 0;
      }
      ```

      结果：

      ![](D:\Desktop\创新创业实践\project4\Snipaste_2023-07-25_15-21-54.png)

      | 数据大小 | 1MB  | 32MB   | 64MB   | 128MB  | 256MB   |
      | -------- | ---- | ------ | ------ | ------ | ------- |
      | 平均用时 | 32ms | 1244ms | 2704ms | 5178ms | 10573ms |

      

   4. 优化效果

      ![](D:\Desktop\创新创业实践\project4\Snipaste_2023-07-25_16-07-59.png)

      最终加速比大约为10。

      

      

2. 环境

   CPU:

   ![](D:\Desktop\创新创业实践\project2\Snipaste_2023-07-20_22-43-35.png)

   软件:

   PyCharm Community Edition 2023.1.4

   Visual Studio 2022
   
   
   
   



#### 2.5 - Impl Merkle Tree following RFC6962

1. 原理

   Merkle Tree是一种哈希树结构，由计算机科学家 Ralph Merkle 发明。它是一种用于验证数据完整性和不可篡改性的数据结构。Merkle Tree 的基本思想是将数据分成若干个块，对每个块进行哈希计算，然后将哈希值再两两配对，再对这些配对的哈希值再次进行哈希计算，重复此过程，直到最后构成一棵树，这棵树的根节点就是整个数据集的哈希值。通过验证根节点的哈希值以及每个数据块的哈希值，可以验证数据的完整性和不可篡改性。Merkle Tree 被广泛应用于比特币和其他加密货币中，用于验证交易的合法性和完整性。在比特币中就是把一笔交易作为一颗Merkle Tree的叶子节点，层层计算得出根节点的哈希值，存储于主链上。

2. 实现

   实现是完全依照文档RFC6962，该文档中没有要求叶子结点是2的幂次，但是Bitcoin中应该是要求是2的幂次，如果不是的话，需要把最后一笔交易复制一份添加到最后形成2的幂次。

   ![](D:\Desktop\创新创业实践\project5\Snipaste_2023-07-30_10-00-57.png)

   关键代码：

   根据输入列表构建Merkle Tree。

   ```python
   def merkle_tree_hash(transactions):
       length = len(transactions)
       if length == 0:
           return None
       if length == 1:
           h = hashlib.sha256()
           h.update(bytes(0x00) + transactions[0].encode('utf-8'))
           return h.hexdigest()
       k = 1
       while not (k < length <= 2 * k):
           k = 2 * k
       left = merkle_tree_hash(transactions[0:k])
       right = merkle_tree_hash(transactions[k:length])
       data = str(0x01) + left + right
       sha = hashlib.sha256()
       sha.update(data.encode())
       return sha.hexdigest()
   ```

   要求中有三个额外需求：

   1. Construct a Merkle tree with 10w leaf nodes

      只需要生成一个包含10w个数据的列表然后利用上述函数构建就可以了。为了简化生成，我取数据为“transaction序号"。

      ```python
      def gen_transactions(num):
          transactions = []
          for i in range(num):
              x = 'transaction'+str(i)
              transactions.append(x)
          return transactions
      ```

   2. Build inclusion proof for specified element

   3. Build exclusion proof for specified element

      第二和第三条要求就是给出特定元素的存在性判定。如果只有根哈希和待判定元素是没法判定的，因为既不知道整棵树的形状也不知道具体其他叶子结点的值，根本无法判断。在比特币网络中判断某笔交易是否真实存在，是需要在主网络上发送一个请求，那些拥有全部数据的节点收到请求后就查询该元素并找出其验证路径然后发送给请求方，请求方根据该元素和验证路径层层计算出根哈希，如果根主链上存储的根哈希值一致就证明该交易是真实存在的。

      如果模拟判定的话首先是需要一个找寻验证路径的函数，RFC6962中也给出了这一实现，遵循文档实现。

      ```python
      def merkle_audit_paths(m, transactions):
          length = len(transactions)
          if length <= 1:
              return []
          k = 1
          while not (k < length <= 2 * k):
              k = 2 * k
          path = []
          if m < k:
              left = merkle_audit_paths(m, transactions[0:k])
              right = merkle_tree_hash(transactions[k:length])
              path = path + left
              path.append(right)
          else:
              left = merkle_audit_paths(m-k, transactions[k:length])
              right = merkle_tree_hash(transactions[0:k])
              path = path + left
              path.append(right)
          return path
      ```

      实现特定元素的存在性判定，假设已知该树所有叶子结点的验证路径和根哈希以及该元素，进行判定。

      根据验证路径判断该元素是否存在，根据元素和一条验证路径判断的时候，不确定该元素处于树的那个位置，所以验证路径的每个值都有两种相对位置情况，所以需要逐个进行验证，只要有一条正确则代表存在。我是直接将所有可能结果存放于列表中，检索里面是否有根哈希，有就代表该元素存在。

      ```python
      def path_proof(element, root_hash, path):
          flag = 0
          all_res = []
          sha = hashlib.sha256()
          sha.update(bytes(0x00) + element.encode())
          all_res.append(sha.hexdigest())
          hash_num = len(path)
          for j in range(hash_num):
              for i in range(len(all_res)):
                  x = all_res[i]
                  temp1 = str(0x01) + x + path[j]
                  temp2 = str(0x01) + path[j] + x
                  sha1 = hashlib.sha256()
                  sha2 = hashlib.sha256()
                  sha1.update(temp1.encode())
                  all_res.append(sha1.hexdigest())
                  sha2.update(temp2.encode())
                  all_res.append(sha2.hexdigest())
          if root_hash in all_res:
              flag = 1
          return flag
      ```

      这里在本地实现所以要先计算出原本所有元素的验证路径，来代替网络询问，逐个的计算比较，只要有一个满足就证明存在。计算所有路径就必须有完整叶子列表。根据上面的“merkle_audit_paths”函数计算每一条路径。

      ```python
      def in_exclusion_proof(element, root_hash, transaction_set):
          flag = 0
          for i in range(len(transaction_set)):
              path = merkle_audit_paths(i, transaction_set)
              flag += path_proof(element, root_hash, path)
          if flag == 1:
              print(element, "inclusion")
          else:
              print(element, "exclusion")
      ```

      测试结果：

      ![](D:\Desktop\创新创业实践\project5\Snipaste_2023-07-30_12-34-19.png)

      测试的时候采用的是10个叶子节点的Merkle Tree，没有采用10w叶节点的Merkle Tree。测试结果正常。

3. 环境

   CPU:

   ![](D:\Desktop\创新创业实践\project2\Snipaste_2023-07-20_22-43-35.png)

   软件:

   PyCharm Community Edition 2023.1.4

   

   

#### 2.6 - impl this protocol with actual network communication

1. 原理

   ![](D:\Desktop\创新创业实践\project6\Snipaste_2023-07-30_20-52-45.png)

   假定今年是2021年，要验证年龄大于21岁，时间节点是2000年。Trusted issuer先选取一个随机种子，然后计算整个哈希链，因为是要持续到2100年，所整个哈希链的长度是123，也就是对选取的种子做依次做123次哈希，得到整个哈希链。将哈希链的首尾哈希发送给Alice，Alice根据首哈希计算出1978到2000对应的哈希链，把最后哈希值和接受的尾哈希发送给Bob校验。Bob根据Alice计算出的最后哈希继续计算得到对应2100年的哈希，如果和尾哈希一致，则验证成功。这样就完成了在Bob不知道Alice具体出生年份的情况下确定Alice年龄大于21岁。

2. 实现

   实现过程中的哈希函数我选用的是sha256。为实现真实网络通信，我为Alice、Bob和Trusted issuer各自写了脚本，三方通信采用的是socket套接字实现通信。然后因为真实情况下网络通信中都是密文传输，不可能直接传输明文，所以我先写了一个CA，Alice、Bob和Trusted issuer首先将各自的公钥发送给CA，然后CA整合后把整个网络中的公钥值发送给他们，这时候Alice、Bob和Trusted issuer三方就可以利用公钥加密然后接收方根据私钥解密实现加密传输。这里我用的是RSA加密解密，填充方案选用的是PKCS1_OAEP，因为填充方案和安全性要求对明文长度有限制，所以为保证发送过程长度不会超过限制，我选取的是2048比特密钥，这样最大明文长度就是214字节，完全足够了。

   因为三方需要进行多次交互，每次都需要socket套接字实现链接，所以每个文件代码都比较长，我就全部放到下面了，具体代码会放到Project-6文件夹中Alice.py,Bob.py,Trusted-issuer.py和CA.py中。下面会通过运行结果图片展示功能实现过程。

   1. Alice、Bob和Trusted issuer通过CA获得各自的公钥值。窗口太小所以显示不全整个公钥表。

      ![](D:\Desktop\创新创业实践\project6\Snipaste_2023-07-30_21-32-08.png)

   2. 完成公钥值共享之后CA完成使命关闭。Alice监听自己的接口，等待Trusted-issuer发送给他信息开始验证。Trusted-issuer监听自己的接口，等待Bob发送开始验证的指令。Bob监听输入，等待开始验证命令。

      ![](D:\Desktop\创新创业实践\project6\Snipaste_2023-07-30_21-33-57.png)

   3. Bob输入y开始整个验证过程，为了更好验证，我把中间计算的值都打印出来，最后Bob验证Trusted-issuer计算的sig_c和自己计算的c_是否一致，一致说明成功验证。

      ![](D:\Desktop\创新创业实践\project6\Snipaste_2023-07-30_21-42-09.png)

   4. 可以重复验证。结束每个验证过程后，三方都会返回第二状态，等待Bob发出开始验证的指令。

      ![](D:\Desktop\创新创业实践\project6\Snipaste_2023-07-30_21-45-29.png)

      

3. 环境

   CPU:

   ![](D:\Desktop\创新创业实践\project2\Snipaste_2023-07-20_22-43-35.png)

   软件:

   PyCharm Community Edition 2023.1.4

   

   

#### 2.7 - Try to Implement this schem

1. 原理

   整个流程图如下，主要组件为KDF、PL-Accum、Shuffle、Padded Sparse MTree以及计算哈希链。KDF函数功能为根据主种子生成多个随机种子用于后续计算。PL-Accum函数主要是平衡优化三个输入。Shuffle函数是随机排序输入的序列。Padded Sparse MTree就是Merkle Tree，恰好四个输入，计算出root为整个输出。

   ![](D:\Desktop\创新创业实践\project7\Snipaste_2023-07-31_09-12-15.png)

2. 实现

   1. KDF

      接受主种子和要生成随机种子的数量，返回生成的随机种子的列表。利用了HMAC和SHA256来生成。

      ```python
      def kdf(master_seed, num_seeds):
          seed_len = len(master_seed)
          hash_algo = hashlib.sha256
          hmac_obj = hmac.new(master_seed, None, hash_algo)
          seeds = []
          for i in range(num_seeds):
              hmac_obj.update(bytes([i]))
              digest = hmac_obj.hexdigest()
              seed = digest[0:seed_len]
              seeds.append(seed)
      
          return seeds
      ```

      

   2. Shuffle

      利用了random库中的shuffle函数进行随机排序。

      ```python
      def shuffle(hash1, hash2, hash3, seed):
          hashes = [hash1, hash2, hash3]
          random.seed(seed)
          random.shuffle(hashes)
          return hashes
      ```

      

   3. PL-Accum

      首先是将输入的哈希值进行处理，计算为浮点数在进行计算。

      ```python
      def pl_accum(hash1, hash2, hash3, eps=1e-6, max_iters=1000):
          data = b"".join([bytes.fromhex(h) for h in [hash1, hash2, hash3]])
          x = np.frombuffer(data, dtype=np.float32)
          f_val = np.sum(x)
          for i in range(max_iters):
              grad = np.ones(3)
              alpha = np.sqrt(i + 1)
              x = x - (1 / alpha) * grad.reshape(-1, 1) * np.ones_like(x)
              f_val_new = np.sum(x)
              if abs(f_val_new - f_val) < eps:
                  break
              f_val = f_val_new
          return x.tobytes()
      ```

      

   4. Padded Sparse MTree

      直接用的是project5中实现的Merkle Tree。

      ```python
      def merkle_tree_hash(transactions):
          length = len(transactions)
          if length == 0:
              return None
          if length == 1:
              h = hashlib.sha256()
              h.update(bytes(0x00) + transactions[0].encode('utf-8'))
              return h.hexdigest()
          k = 1
          while not (k < length <= 2 * k):
              k = 2 * k
          left = merkle_tree_hash(transactions[0:k])
          right = merkle_tree_hash(transactions[k:length])
          data = str(0x01) + left + right
          sha = hashlib.sha256()
          sha.update(data.encode())
          return sha.hexdigest()
      ```

   5. generalizing_hash_chains

      整个流程，组合上面的组件，计算中过程值。

      ```python
      def generalizing_hash_chains():
          master_key = secrets.token_hex(16)
          seed_set = kdf(master_key.encode(), 8)
      
          seed_d = seed_set[0]
          seed_1 = seed_set[1]
          seed_2 = seed_set[2]
          seed_3 = seed_set[3]
          salt_a = seed_set[4]
          salt_b = seed_set[5]
          salt_c = seed_set[6]
          shuffle_seed = seed_set[7]
      
          seed_d_chain = hash_chains(seed_d, 9)
          seed_1_chain = hash_chains(seed_1, 3)
          seed_2_chain = hash_chains(seed_2, 3)
          seed_3_chain = hash_chains(seed_3, 3)
      
          a = pl_accum(seed_3_chain[3], seed_2_chain[1], seed_1_chain[2])
          b = pl_accum(seed_3_chain[3], seed_2_chain[0], seed_1_chain[3])
          c = pl_accum(seed_3_chain[2], seed_2_chain[3], seed_1_chain[3])
      
          h = hashlib.sha256()
      
          h.update(salt_a.encode() + a)
          A = h.hexdigest()
          h.update(salt_b.encode() + b)
          B = h.hexdigest()
          h.update(salt_c.encode() + c)
          C = h.hexdigest()
      
          leaf_list = shuffle(A, B, C, shuffle_seed)
          leaf_list.append(seed_d_chain[-1])
      
          root = merkle_tree_hash(leaf_list)
      
          return root
      ```

      测试结果：

      流程正常执行，执行10次总用时为0.04262秒，1次用时大约为0.0043秒。

      ![](D:\Desktop\创新创业实践\project7\Snipaste_2023-07-31_09-27-55.png)

   

3. 环境

   CPU:

   ![](D:\Desktop\创新创业实践\project2\Snipaste_2023-07-20_22-43-35.png)

   软件:

   PyCharm Community Edition 2023.1.4

   

   

#### 2.8 - AES impl with ARM instruction

1. 原理

   ARM 指令是一组用于 ARM 架构处理器的机器指令，用于执行特定的操作。ARM 指令被编码为 32 位定长指令，可以直接由处理器硬件执行。ARM 指令集被设计为简洁、高效和灵活，可以在不同的处理器实现之间共享，从而提高了代码可移植性。还包括多种指令类型。并且还具有可扩展性，允许处理器设计人员添加自定义指令以满足特定的应用需求。

   因为ARM指令是底层的指令集，纯正手工实现非常麻烦，于是我想到了之前计算机系统原理实验课上用过的arm-linux-gnueabi-gcc交叉编译工具，可以实现将x86架构代码编译为ARM架构的可执行文件，编译完成后该文件就是利用ARM指令实现的AES。所以首先是需要实现一版C语言的AES，之后利用arm-linux-gnueabi-gcc编译为ARM架构的可执行文件，这时候该文件就是利用ARM指令实现的，最后可以通过qemu模拟器验证是否正确执行。

2. 实现

   1. 首先是实现C版本的AES，详细代码在project-8文件夹中AES.c，这里给出测试代码。测试代码中的密钥和明文选取是根据NIST发布的AES标准设定的，加密结果也跟标准中给出的结果对比。标准设定如下：

      ![](D:\Desktop\创新创业实践\project8\Snipaste_2023-07-25_23-27-56.png)

      ![Snipaste_2023-07-25_23-28-20](D:\Desktop\创新创业实践\project8\Snipaste_2023-07-25_23-28-20.png)

      测试代码：

      ```c
      int main() 
      {
          uint8_t key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
          uint8_t pt[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
          uint8_t ct[16] = { 0 };     
          uint8_t plain[16] = { 0 };  
          aesEncrypt(key, 16, pt, ct, 16); 
          printHex(pt, 16, "plain data:"); 
          printf("expect cipher:\n69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a\n"); 
          printHex(ct, 16, "after encryption:"); 
          aesDecrypt(key, 16, ct, plain, 16);      
          printHex(plain, 16, "after decryption:"); 
          return 0;
      }
      ```

      测试结果：

      ![](D:\Desktop\创新创业实践\project8\Snipaste_2023-07-25_23-30-12.png)

      结果是完全一样的，说明加解密算法流程是正确的。

   2. 利用arm-linux-gnueabi-gcc进行交叉编译。这个是linux版本的，所以需要在虚拟机中实现。安装和其他包一样正常安装，但是在运行时会报错，说缺少ld-linux.so.3，首先利用命令查看是否存在该文件发现存在但不在该路径下，所以就直接复制过来就可以。再次运行这个错误消失，但出现了缺少libc.so.6，跟上述操作一样直接找到该文件直接复制到该路径下，成功解决。

      ![](D:\Desktop\创新创业实践\project8\Snipaste_2023-07-25_23-36-59.png)

      执行完命令后查看该执行文件的架构信息，可以看出确实为ARM架构。交叉编译成功。

   3. 测试生成的ARM架构可执行文件是否正确。因为我自己电脑是x86架构的，所以无法直接运行。只能安装一个qemu arm模拟器来运行测试。安装也和其他软件类似。运行结果如下图，可以发现运行结果正确。此时，AES_ARM就是基于AEM架构的AES-128的实现。

      ![](D:\Desktop\创新创业实践\project8\Snipaste_2023-07-25_23-40-16.png)

3. 环境

   CPU:

   ![](D:\Desktop\创新创业实践\project2\Snipaste_2023-07-20_22-43-35.png)

   软件:

   Visual Studio 2022

   Ubuntu 20.04

   

   

#### 2.9 - AES / SM4 software implementation

1. 原理

   AES，高级加密标准，是美国采用的一种区块加密标准，也是目前最流行的对称加密算法之一。明文块长度为128比特，密钥长度可以是128、192或256比特，分别对应不同的轮数。其中大多数运算是在$GF({2^8})$有限域完成的。而且所有操作是在一个 4*4 的字节矩阵上完成的。加密算法主要包含四个操作，分别为`AddRoundKey`，`SubBytes`，`ShiftRows`和`MixColumns`。解密算法操作为加密算法的逆运算且顺序稍有不同。

   SM4，是我国采用的一种分组密码标准。算法公开，分组长度和密钥长度均为128比特，加密算法与密钥扩展算法都采用了32轮的非线性迭代结构，S盒是固定的8比特输入8比特输出。

2. 实现

   1. AES-Python

      具体代码放在project-9文件夹中的AES.py。

      首先验证算法是否正确，检验标准是根据NIST标准文档给出的示例明密文和主密钥。

      然后测试算法时间开销，计算一次加解密开销采用重复一万次求平均。

      测试代码：

      ```python
      def test():
          master_key = '000102030405060708090a0b0c0d0e0f'
          message = '00112233445566778899aabbccddeeff'
          cipher_text = bytes.hex(encrypt(bytes.fromhex(message), bytes.fromhex(master_key)))
          plain_text = bytes.hex(decrypt(bytes.fromhex(cipher_text), bytes.fromhex(master_key)))
          print("plain data:\n", message)
          print("expect cipher:\n 69c4e0d86a7b0430d8cdb78070b4c55a")
          print("after cipher:\n", cipher_text)
          print("after decryption:\n", plain_text)
      
          print('------------------------------------')
      
          mk = bytes(gen_random_string(16), "utf-8")
          m = bytes(gen_random_string(16), "utf-8")
          start_time = time.time()
          for i in range(10000):
              cipher = encrypt(m, mk)
              plain = decrypt(cipher, mk)
          end_time = time.time()
          use_time = end_time - start_time
          print("加解密 10000 次总用时为 :", use_time, " 秒")
          print("加解密 1 次平均用时为 :", use_time / 10000, " 秒")
      ```

      测试结果：

      加密解密结果符合标准示例，说明算法正确。时间开销方面，加解密128比特明文分组时间为0.000521秒，约为0.5毫秒。

      ![](D:\Desktop\创新创业实践\project9\Snipaste_2023-07-26_09-37-00.png)

   2. AES-C

      具体代码为Project-9文件夹中AES.c

      跟上面一样先验证加解密是否正确，再测试时间开销。

      测试代码：

      ```c
      int main() 
      {
          uint8_t key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
          uint8_t pt[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
          uint8_t ct[16] = { 0 };     
          uint8_t plain[16] = { 0 };  
          aesEncrypt(key, 16, pt, ct, 16); 
          printHex(pt, 16, "plain data:"); 
          printf("expect cipher:\n69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a\n"); 
          printHex(ct, 16, "after encryption:"); 
          aesDecrypt(key, 16, ct, plain, 16);      
          printHex(plain, 16, "after decryption:"); 
      
          printf("------------------------------------------------\n");
          clock_t start, end;
          double cpu_time_used;
      
          uint8_t k[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
          uint8_t p[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
          uint8_t cipher_text[16] = { 0 };
          uint8_t plain_text[16] = { 0 };
      
          start = clock();
          for (int i = 0;i < 100000;i++)
          {
              aesEncrypt(k, 16, p, cipher_text, 16);
              aesDecrypt(k, 16, cipher_text, plain_text, 16);
          }
          end = clock();
      
          cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
          printf("加解密 100000 次总用时为 : %f 秒\n", cpu_time_used);
          printf("加解密 1 次总用时为 : %f 秒\n", cpu_time_used / 100000);
      
          return 0;
      }
      ```

      测试结果：

      加解密结果符合标准示例。加解密一次128比特明文分组平均用时为0.000038秒，约为0.038毫秒。

      ![](D:\Desktop\创新创业实践\project9\Snipaste_2023-07-26_10-02-34.png)

   3. SM4-C

      具体代码在Project-9中的SM4.c

      还是先验证正确性再测试效率。正确性是根据官方文档给出的示例。

      ![](D:\Desktop\创新创业实践\project9\Snipaste_2023-07-31_10-44-45.png)
      
      ![](D:\Desktop\创新创业实践\project9\Snipaste_2023-07-31_09-58-26.png)
      
      测试代码：
      
      ```c
      int main() {
          char* str = "0123456789ABCDEFFEDCBA9876543210";
          uint32_t k[4];
          uint32_t M[4];
          for (int i = 0; i < 4; i++) {
              char substr[9];
              memcpy(substr, str + i * 8, 8);
              substr[8] = '\0';
              k[i] = strtoul(substr, NULL, 16);
              M[i] = strtoul(substr, NULL, 16);
          }
          uint32_t key[36];
          key_expand(k, key);
          printf("%s\n", "------对一组明文加密 1 次示例------");
          printf("%s", "输入明文 :");
          show(M);
          printf("%s", "输入密钥 :");
          show(k);
          SM4_encrypt(M, key);
          printf("%s", "输出密文 :");
          show(M);
          SM4_decrypt(M, key);
          printf("%s", "输出明文 :");
          show(M);
          printf("%s\n", "------对一组明文反复加密 1 000 000 次示例------");
          printf("%s", "输入明文 :");
          show(M);
          printf("%s", "输入密钥 :");
          show(k);
          clock_t start, end;
          double mtime;
          start = clock();
          for (int i = 0;i < 1000000;i++)
          {
              SM4_encrypt(M, key);
          }
          end = clock();
          mtime = (double)(end - start) * 1000 / CLOCKS_PER_SEC;
          printf("%s", "输出密文 :");
          show(M);
          SM4_decrypt(M, key);
          printf("%s", "输出明文 :");
          show(M);
          printf("程序运行时间：%f 毫秒\n", mtime);
          return 0;
      }
      ```
      
      测试结果：
      
      加密结果和官方文档给出的示例一致，正确。时间开销方面，加密1000000次16字节用时669毫秒，换算一下，加密速度大约为23MB/s。
      
      ![](D:\Desktop\创新创业实践\project9\Snipaste_2023-07-31_10-44-03.png)

3. 环境

   CPU:

   ![](D:\Desktop\创新创业实践\project2\Snipaste_2023-07-20_22-43-35.png)

   软件:

   PyCharm Community Edition 2023.1.4

   Visual Studio 2022

   

   

   

#### 2.10 - report on the application of this deduce technique in Ethereum with ECDSA



​															ECDSA从签名技术推导公钥在以太坊应用情况研究报告

一、背景介绍

​		以太坊是一种基于区块链技术的去中心化平台，用于构建分布式应用程序。在以太坊中，使用椭圆曲线数字签名算法（ECDSA）来验证交易的有效性和保护账户的安全性。在某些情况下，需要从签名中推导出公钥，例如验证交易发送方的身份或者进行离线交易签名。以太坊中使用的椭圆曲线数字签名算法ECDSA是一种基于椭圆曲线的数字签名算法，与RSA相比，具有更高的安全性和更小的密钥长度。ECDSA算法包括三个主要步骤：密钥生成、签名和验证。



二、简述Deduce public key from signature（从签名中推导公钥）过程

1. 从签名中提取r和s值。
2. 计算哈希值，并将其转换为椭圆曲线上的点。假设哈希值为h，转换后的点为P。
3. 计算一个值K，使K*G（G为椭圆曲线上的基点）等于该点。这个过程可以使用随机数生成器来生成K，或者使用确定性K值的方法。
4. 计算一个值R，使得R = (s^-1)（KG - r*P），其中s^-1为s的逆元，P为第二步计算出来的点。
5. 从R中提取公钥。具体方法取决于使用的椭圆曲线参数。

从ECDSA签名中推导公钥的过程需要使用椭圆曲线点乘算法，具体步骤包括从签名中提取r和s值、计算哈希值并转换为椭圆曲线上的点、计算随机数K、计算R值、从R中提取公钥。



三、应用情况

在以太坊中，使用椭圆曲线数字签名算法（ECDSA）来验证交易的有效性和保护账户的安全性。在某些情况下，需要从签名中推导出公钥。主要包括以下两种情况：

- [ ] 验证交易发送方的身份

  当一个交易被提交到以太坊网络时，需要验证发送方的身份。需要从交易中提取签名和消息。交易包括交易发送方的地址、接收方的地址、转账金额、交易费用等信息。签名包括r和s两个值，是由发送方使用私钥对消息进行签名得到的。然后计算消息的哈希值，并将其转换为椭圆曲线上的点。哈希值是由交易信息计算得到的，可以使用Keccak-256等哈希算法。转换为椭圆曲线上的点需要使用特定的转换方法。由于交易中只包含发送方的地址而不包含公钥，因此需要从签名中推导出公钥，以便进行验证。

- [ ] 离线交易签名

  有时候需要在离线设备上进行交易签名，但是没有访问以太坊网络的权限。在这种情况下，可以在离线设备上使用私钥对交易进行签名，并将签名和公钥传输到联网设备上进行广播。具体步骤包括，首先在离线设备上生成一个钱包，并记录下私钥和公钥。然后在联网设备上创建一个交易，并将交易信息传输到离线设备上。然后在离线设备上使用私钥对交易进行签名，得到签名和公钥。最后将签名和公钥传输回联网设备，并将其用于广播交易。在这个过程中，需要使用Deduce public key from signature的方法来从签名中推导出公钥信息。

- [ ] 验证数字证书的有效性

  在TLS等加密通信协议中，可以使用Deduce public key from signature来验证数字证书的有效性。具体地，从数字证书中提取签名和证书信息，并使用Deduce public key from signature方法推导出公钥。然后，使用公钥和证书信息来验证签名的有效性，从而确定数字证书的合法性。

- [ ] 数字水印

  在数字水印技术中，可以使用Deduce public key from signature来验证数字水印的有效性。具体地，将数字水印嵌入到消息中，并使用私钥对消息进行签名。然后，将签名和公钥嵌入到消息中，并传输到接收方。接收方使用Deduce public key from signature方法从签名中推导出公钥，并使用公钥和消息来验证签名的有效性，从而确定数字水印的合法性。

  

四、安全隐患

​		Deduce public key from signature在以太坊中用于完成交易签名和双方验证，地位非常重要。但是这个推导方法还是存在一些安全隐患，主要有以下几个安全隐患：

- 中间人攻击

  攻击者可以在传输过程中篡改消息，从而修改哈希值和签名。这可能导致推导出的公钥不正确，从而验证签名的有效性失败。

- 恶意签名

  攻击者可以故意生成一个无效的签名，使其能够推导出一个虚假的公钥。这可能会导致验证交易发送方的身份或进行离线交易签名时出现错误。

- 签名重用

  攻击者可以使用同一个签名来伪造多个交易，从而导致多个交易被认为是有效的。

​		为了避免这些安全隐患，提高交易的安全性以及保护交易双方的权益，需要采用一些措施来保护数字签名的安全性。例如，使用HTTPS等加密协议来保护消息的传输安全；使用随机数等技术来增加签名的随机性，降低签名重用的风险；使用多重签名等技术来增加交易的安全性。此外，还需特别注意保护私钥的安全，避免私钥泄露。



五、总结

​		Deduce public key from signature广泛应用于区块链、加密通信、数字水印等领域。在区块链中，Deduce public key from signature常用于验证交易发送方的身份和进行离线交易签名。在加密通信中，Deduce public key from signature常用于验证数字证书的有效性。在数字水印领域，Deduce public key from signature常用于验证数字水印的有效性。但其还存在一些安全隐患，如中间人攻击、恶意签名和签名重用等问题。为了保证数字签名的安全性，需要采取多种措施，如使用HTTPS等加密协议、增加签名的随机性、使用多重签名等技术等。性能方面较好，计算复杂度较低，可以快速地推导出公钥。但是，在大规模应用中，由于需要进行大量的数字签名验证，仍然需要考虑性能问题。目前，Deduce public key from signature的研究主要集中在改进算法、提高安全性和性能等方面。例如，有研究提出了基于椭圆曲线上的非交互式数字签名算法（ECQV）来替代Deduce public key from signature，以提高安全性和性能。总之，Deduce public key from signature是一种重要的数字签名验证方法，在多个领域得到广泛应用。未来随着技术的不断发展，Deduce public key from signature的安全性和性能将得到进一步提高。







#### 2.11 - impl sm2 with RFC6979

1. 原理

   RFC6979描述的是确定性的DSA和ECDSA，也就是确定性的数字签名算法和确定性的基于椭圆曲线的数字签名算法。和标准的DSA和ECDSA的区别主要在于随机值 k 的选取，标准实现是随机选取值是不确定的，确定性的算法描述了一种可以生成确定k值的随机k生成过程。这样相比较于标准算法，可以更容易在各种环境中实现，因为不需要访问高质量的随机数来源，同时安全性没有任何降低。

   ![](D:\Desktop\创新创业实践\project11\Snipaste_2023-08-02_14-41-49.png)

   

2. 实现

   首先说明DSA和ECDSA的计算流程是相同的，不同点仅在于DSA是在一个有限域内进行的计算，ECDSA是在一个椭圆曲线上进行运算。两个算法只在值的计算方面有一点不同，其余流程都是一样的。因为SM2是基于椭圆曲线的公钥加密算法，所以我选择实现ECDSA，其实换个参数和计算方法就是DSA。下面我根据文档从四方面介绍实现，第一个是ECDSA的关键参数，后面的所有运算几乎都离不开其中的q和G，参数不同生成的确定性随机值k和最后的签名值也是不同的。第二个是算法中需要的转换函数，算法中有很多地方需要特定的数据类型，所以需要多个转换函数，文档对转换函数有具体要求，单纯实现对应功能无法成功实现整个算法。第三个是生成签名的流程，主要包括生成确定性随机值k以及在椭圆曲线上计算r和s。第四个是生成确定性随机值k的流程，这是文档的主要部分，也正是有这一流程才能完成标准ECDSA到确定性ECDSA的转化。

   - 文档给出了ECDSA的关键参数。

     ![](D:\Desktop\创新创业实践\project11\Snipaste_2023-08-02_15-14-04.png)

     实现过程中的参数取值我是根据文档末尾的示例中给出的值取定的。一是防止参数不匹配算法无法进行，二是文档给出了固定参数下的详细中间值，便于代码调试和结果验证。具体值如下。给出了选择的曲线以及关键参数的值。而且后面还有每个步骤后中间值的具体值。

     ![](D:\Desktop\创新创业实践\project11\Snipaste_2023-08-02_15-12-44.png)

   

   

   - 文档算法流程中涉及很多数据结构类型的转变函数。一开始没有参考文档直接实现对应的转变，但结果和文档给出的示例不符，之后仔细查看文档发现，转换函数有特殊的限制和要求，例如函数int2octets，要求如下，要求是使用SEC 1 文档中定义的该函数。还有因为转换函数类型变化比较大，每次使用时都要检查输入输出类型，很麻烦，为了简化后续签名和生成k过程的使用，我统一把输入输出都改为bytes类型，除了涉及 int 型变量的输入输出没有改动，因为很多是直接参与运算的。还有就是这些实现都是按照文档给出的流程编写的。实现过程中需要注意的就是文档中给出的qlen、rlen和blen三个值。文档给出了三个值的说明。首先是blen，因为文档中流程都是在比特序列上操作，所以blen是比特序列的长度。然后是qlen，它其实是参数q的二进制位数，二进制串最左侧为一。最后是rlen，rlen是大于等于qlen的最小的八的倍数。在我选取的参数值下，qlen是163，rlen是168，blen就是根据操作的比特串计算。

     ![](D:\Desktop\创新创业实践\project11\Snipaste_2023-08-02_15-04-26.png)

     1. Bit String to Integer

        ```python
        def bits2int(b):
            b = b.hex()
            b = int(b, 16)
            b = all2bits(b)
            b = b.decode()
            blen = len(b)
            if qlen < blen:
                b = b[0:qlen]
            else:
                b = '0' * (qlen - blen) + b
            res = int(b, 2)
            return res
        ```

        

     2. Integer to Octet String

        ```python
        def int2octets(x):
            mlen = 21
            if x > q:
                x = x % q
            X = []
            xx = all2bits(x)
            for j in range(0, 168, 8):
                xxx = xx[j:j+8]
                X.append(int(xxx, 2))
            M = []
            for i in range(mlen):
                M.append(X[i])
            return bytes(M)
        ```

        

     3. Bit String to Octet String

        ```python
        def bits2octets(b):
            b = b.hex()
            b = int(b, 16)
            b = all2bits(b)
            z1 = bits2int(b)
            z2 = z1 % q
            res = int2octets(z2)
            return res
        ```

        

   - 文档中签名生成的流程实现。四个大步骤完成。

     ![](D:\Desktop\创新创业实践\project11\Snipaste_2023-08-02_15-35-47.png)

     ```python
     def sign_deterministic(msg):
         hm = hash_func(msg)
         h = bits2int(hm) % q
         k = deterministic_k(msg)
         r = k * Gx % q
         s = int(((h + x * r) / k) % q)
         return r, s
     ```

     

   - 生成确定性随机值k的实现。完全遵循的文档中的流程。因为我选用的哈希函数是SHA256,HMAC中也是SHA256，所以下面初始化V和K是字节数是32。HMAC函数hmac_sha256就是根据hmac和hashlib第三方库实现的。

     ```python
     def deterministic_k(msg):
         h1 = hash_func(msg)
         V = b'\x01' * 32
         K = b'\x00' * 32
         K = hmac_sha256(K, V + b'\x00' + int2octets(x) + bits2octets(h1))
         V = hmac_sha256(K, V)
         K = hmac_sha256(K, V + b'\x01' + int2octets(x) + bits2octets(h1))
         V = hmac_sha256(K, V)
         
         while True:
             T = b''
             tlen = 0
             while tlen < qlen:
                 V = hmac_sha256(K, V)
                 T = T + V
                 print('T', T.hex())
                 tlen = len(T) * 8
             k = bits2int(T)
             if 0 < k < q:
                 break
             else:
                 K = hmac_sha256(K, V + b'\x00')
                 V = hmac_sha256(K, V)
                 print('K', K.hex())
                 print('V', V.hex())
     
         return k
     ```

   - 运行结果

     一开始是没有严格按照文档说明实现，显然运行失败，之后我就仔细看了文档，把之前实现的都修改为了文档中给出的流程，最后代码为上面展示的，完整代码在github上project-11中。因为我是按照文档后面的详细示例选取的参数和明文消息，所以我可以根据文档的中间值查看哪一步出现了错误，最后经过对照还是转换函数的问题，bits2octets函数在处理明文消息的哈希值的时候结果错误，导致后面的都是错的。

     正确结果为：

     ![](D:\Desktop\创新创业实践\project11\Snipaste_2023-08-02_15-52-14.png)

     ![Snipaste_2023-08-02_15-52-29](D:\Desktop\创新创业实践\project11\Snipaste_2023-08-02_15-52-29.png)

     运行结果：

     ![](D:\Desktop\创新创业实践\project11\Snipaste_2023-08-02_15-51-46.png)

     发现错误后我就继续对照文档检查该函数，但是一直就是没有找到错误在哪。运行程序就陷入死循环始终找不到正确的k值。

     

     模拟时间开销：

     ![](D:\Desktop\创新创业实践\project11\Snipaste_2023-08-02_16-06-18.png)

     文档中给出了生成出k值的步骤，内层循环执行三次就可以生成。因为是确定性算法，所以正常执行后流程和中间值和文档中给出的是一模一样的，当然这是明文消息为‘sample’时的数据。完成一次大约是0.00008s

     

3. 环境

   CPU:

   ![](D:\Desktop\创新创业实践\project2\Snipaste_2023-07-20_22-43-35.png)

   软件:

   PyCharm Community Edition 2023.1.4

   

   

   

#### 2.12 - verify the above pitfalls with proof-of-concept code	

1. 原理

   ![](D:\Desktop\创新创业实践\project12\Snipaste_2023-08-03_23-00-43.png)

   上图是要求验证的所有签名陷阱。这些陷阱有一些是通过数学推导得出的，像前两个和最后一个，类似于解方程，只要条件够了就可以计算出方程的解也就是私钥d。其他的也都是因为针对某些参数的限制放宽导致可以进行一些恶意攻击。这里我实现了ECDSA中的Leaking k leads to leaking of d、Reusing k leads to leaking of d以及Same d and k with ECDSA leads to leaking of d。采用的是之前课件给出的ECDSA签名和验证算法。下面介绍实现时，我会加上推导过程，之后是代码实现。

   ![](D:\Desktop\创新创业实践\project12\Snipaste_2023-08-04_00-13-11.png)

2. 实现

   - Leaking k leads to leaking of d

     原理：

     前提条件是我们已知消息m、公钥P、m的签名值。具体到算法是我们知道了r，s，e三个参数。这时候k泄露了，说明我们也知道了k。根据签名过程中s的计算公式，公式中只有d不知道，只需要都带入就可以计算出d。

     ![](D:\Desktop\创新创业实践\project12\Snipaste_2023-08-04_00-18-26.png)

     代码实现：

     假设k值是10000。为了使签名过程中k确实为10000，这里在签名函数中我用第二个参数来控制k的具体数值，为零代表10000。

     计算出签名后就带入计算就可以得出d。

     ```python
     def leaking_k_leaking_d_test():
         k = 10000
         m = secrets.token_bytes(16)
         e = int(hash_func(m).hex(), 16)
         sig = sign(m, 0)
         r = sig[0]
         s = sig[1]
         dd = (inverse(r, n) * (s * k - e)) % n
         if dd == d:
             print('恢复出私钥 : ', dd)
         else:
             print('恢复私钥失败')
     ```

     

   - Reusing k leads to leaking of d

     原理：

     原理类似于上面的陷阱，不同在于不知道k的具体数值，但是直到多个用k进行签名的消息和签名。因为私钥是不变的，所以会出现多个$s_i = k^{-1} * (e_i + d * r_i) % n$，方程中有两个未知数，至少两个签名值对就可以计算出k和d的具体数值。

     代码实现：

     ```python
     def reusing_k_leaking_d_test():
         m1 = secrets.token_bytes(16)
         m2 = secrets.token_bytes(16)
         sig1 = sign(m1, 0)
         sig2 = sign(m2, 0)
         e1 = int(hash_func(m1).hex(), 16)
         e2 = int(hash_func(m2).hex(), 16)
     
         r1 = sig1[0]
         s1 = sig1[1]
         r2 = sig2[0]
         s2 = sig2[1]
     
         k = inverse(s1 * inverse(r1, n) - s2 * inverse(r2, n), n) * (e1 * inverse(r1, n) - e2 * inverse(r2, n)) % n
     
         dd = (inverse(r1, n) * (s1 * k - e1)) % n
         if dd == d:
             print('恢复出私钥 : ', dd)
         else:
             print('恢复私钥失败')
     ```

     

   - Same d and k with ECDSA leads to leaking of d

     原理：

     原理和上面两个类似，都是解方程问题，根据公式$s = k^{-1} * (e + d * r) % n $，再加上k和d相同，整个方程又只剩一个未知数，直接带入就可以计算出私钥d。

     代码实现：

     这里签名函数第二个参数为2，代表k选择和我设定的私钥d相同。

     ```python
     def same_d_k_leaking_d_test():
         m = secrets.token_bytes(16)
         e = int(hash_func(m).hex(), 16)
         sig = sign(m, 2)
         r = sig[0]
         s = sig[1]
     
         dd = inverse(s - r, n) * e % n
         if dd == d:
             print('恢复出私钥 : ', dd)
         else:
             print('恢复私钥失败')
     ```

   - [ ] 运行结果

     运行结果跟参数选取相对应，所以首先确定我的参数选择如下。d为私钥，P为公钥。

     ```python
     # ECDSA parameters
     p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
     n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
     q = 0x4000000000000000000020108A2E0CC0D99F8A5EF
     x = 0x09A4D6792295A7F730FC3F2B49CBC0F62E862272F
     Gx = 0x79AEE090DB05EC252D5CB4452F356BE198A4FF96F
     Gy = 0x782E29634DDC9A31EF40386E896BAA18B53AFA5A3
     d = 9876543210123456789
     P = (d * Gx % n, d * Gy % n)
     ```

     ![](D:\Desktop\创新创业实践\project12\Snipaste_2023-08-04_00-34-05.png)

     还需要说明一下签名函数，因为三个陷阱测试对k的要求不同，为了能控制k的取值，我在签名函数参数列表中加了krand，用来控制k的取值。为0时用于第二个测试，设定为已知。为2时用于第三个测试，取值和私钥d保持一致。其他时候都是随机选取。

     ```python
     def sign(msg, krand=1):
         if krand == 0:
             k = 10000
         elif krand == 2:
             k = 9876543210123456789
         else:
             k = random.randint(1, n - 1)
         R = (k * Gx % n, k * Gy % n)
         r = R[0] % n
         e = int(hash_func(msg).hex(), 16) % n
         s = inverse(k, n) * (e + d * r) % n
         return r, s
     ```

     

3. 环境

   CPU:

   ![](D:\Desktop\创新创业实践\project2\Snipaste_2023-07-20_22-43-35.png)

   软件:

   PyCharm Community Edition 2023.1.4











#### 2.13 - Implement the above ECMH scheme

1. 原理

   Elliptic curve MultiSet Hash（ECMH）是一种哈希算法，它基于椭圆曲线的离散对数难题，可以将任意大小的数据集映射到一个固定长度的哈希值上。ECMH的核心思想是将数据集中的元素映射到椭圆曲线上，并将这些点相加得到一个新的点，再将这个点的坐标作为哈希值输出。具有高效地处理大规模数据集并且时间复杂度与数据集大小无关；较强的安全性，基于椭圆曲线的离散对数难题，难以被暴力破解；哈希值长度固定，可以方便地用于数据校验和身份验证等场景等功能。流程图如下，具体计算流程包括，首先将数据集中的元素通过哈希函数映射到一个椭圆曲线上，得到一组点。然后对这组点进行去重和排序，得到一个多重集合。之后将多重集合中的每个元素重复出现对应的次数，得到一个新的多重集合。之后将新的多重集合中的所有元素对应的点相加，得到一个新的点。最后将新的点的坐标作为哈希值输出。

   ![](D:\Desktop\创新创业实践\project13\Snipaste_2023-08-03_09-30-45.png)

2. 实现

   实现了一个简易的ECMH，可以完成基本的功能。实现采用的是Python，创建了一个class类ECMH，让代码更规范更清晰。主要包括四个函数，一个是初始化函数，一个是添加函数，一个是删除函数，还有一个计算最后输出哈希的函数。

   1. 初始化函数。定义了ECMH使用的椭圆曲线，椭圆曲线的无穷远点和哈希-出现次数键值对字典。

      ```python
          def __init__(self, curve=SECP256k1):
              self.curve = curve
              self.infinity = curve.generator * 0
              self.counts = {}
      ```

      

   2. 添加函数。对每一个消息计算哈希值然后存储到字典中，相同的只增加出现次数。

      ```python
          def add(self, msg):
              h = hashlib.sha256(msg.encode()).digest()
              if h in self.counts:
                  self.counts[h] += 1
              else:
                  self.counts[h] = 1
      ```

      

   3. 删除函数。当删除一个消息时，如果该消息不在列表中就不进行操作，如果存在检查出现次数，如果还有其他的就只减少出现次数，否则直接删除该哈希值。

      ```python
          def remove(self, msg):
              h = hashlib.sha256(msg.encode()).digest()
              if h in self.counts:
                  if self.counts[h] > 1:
                      self.counts[h] -= 1
                  else:
                      del self.counts[h]
      ```

      

   4. 计算结果哈希值。第一步是根据哈希出现的次数排序字典。然后计算每个元素对应的椭圆曲线上的点并相加得到最终结果。

      ```python
          def digest(self, k):
              sorted_hashes = sorted(self.counts.keys(), key=lambda h: -self.counts[h])
              sk = SigningKey.from_secret_exponent(k, curve=self.curve)
              h = hashlib.sha256()
              p = self.infinity
              for h_i in sorted_hashes:
                  for _ in range(self.counts[h_i]):
                      p = p + (bytes2int(sk.sign(h_i)) * self.curve.generator)
              h.update(p.x().to_bytes(32, 'big'))
              return h.digest()
      ```

      

   测试结果：

   ​		功能可以正常实现。

   ![](D:\Desktop\创新创业实践\project13\Snipaste_2023-08-03_09-58-20.png)

3. 环境

   CPU:

   ![](D:\Desktop\创新创业实践\project2\Snipaste_2023-07-20_22-43-35.png)

   软件:

   PyCharm Community Edition 2023.1.4

   

   

   

#### 2.14 - Implement a PGP scheme with SM2

1. 原理

   加密工作原理如下图。加密方用对称密码加密想要传输的明文，加密时采用的密钥是随机生成的会话密钥。然后用接收方的公钥加密生成的会话密钥。将这两部分密文发送给接收方。题目要求公钥加密部分采用的是SM2算法，对称密码没有具体要求我使用的是AES-CBC。

   ![](D:\Desktop\创新创业实践\project14\Snipaste_2023-07-31_16-30-22.png)

   解密工作原理如下图。接收方收到密文后首先是将两部分密文分开，然后利用自己的SM2私钥解密会话密钥，然后用会话密钥解密明文对应的密文。完成传输。

   ![](D:\Desktop\创新创业实践\project14\Snipaste_2023-07-31_16-30-42.png)

2. 实现

   没有进行真实的网络通信实现，是模拟流程进行。真实环境中接发双方都有各自的SM2公钥和私钥对，实现中采用了相同的公私钥对进行模拟实现。实现中的AES解密解密实现是基于Crypto库，SM2加密解密实现是基于Gmssl库的。

   PGP加密实现：

   ```python
   def pgp_encrypt(message):
       message_bytes = message.encode()
       session_key = secrets.token_hex(16)
       session_key_bytes = session_key.encode()
       cipher_message = aes_encrypt(message_bytes, session_key_bytes)
       cipher_session_key = sm2_encrypt(session_key)
       a = aes_decrypt(cipher_message, session_key_bytes)
       return cipher_message, cipher_session_key
   ```

   PGP解密实现：

   ```python
   def pgp_decrypt(cipher_message, cipher_session_key):
       session_key = sm2_decrypt(cipher_session_key)
       message = aes_decrypt(cipher_message, session_key.encode())
       return message
   ```

   PGP测试：

   代码：

   ```python
   def pgp_test():
       message = secrets.token_hex(32)
       print('Message :', message)
       cm, ck = pgp_encrypt(message)
       print("Cipher-Message :", cm)
       print("Cipher-Session-Key :", ck)
       plain = pgp_decrypt(cm, ck)
       print("Plain :", plain)
       if plain == message:
           print("PGP-SM2-AES Success")
   ```

   结果：PGP scheme成功实现。

   ![](D:\Desktop\创新创业实践\project14\Snipaste_2023-07-31_16-45-02.png)

3. 环境

   CPU:

   ![](D:\Desktop\创新创业实践\project2\Snipaste_2023-07-20_22-43-35.png)

   软件:

   PyCharm Community Edition 2023.1.4

   

   

   

#### 2.15 - implement sm2 2P sign with real network communication

1. 原理

   SM2 two-party  sign是通过将SM2签名过程分成两个部分，在两个不同的设备上进行，来保证私钥的安全性。具体流程如下图：

   ![](D:\Desktop\创新创业实践\project15\Snipaste_2023-08-01_10-20-12.png)

   在这个过程中设备A（图上左边）只知道子私钥d1，消息 M，随机数k1，设备B（图上右边）只知道子私钥d2，可以计算出的公钥P，随机数k2和k3。整个过程中没有真正的私钥出现，传输过程中的数据都是一些根据随机数生成的随机值，没有任何地方会泄露有效信息。但是进一步加强安全性，传输过程中应该还是使用密文传输，以及加入MAC甚至是数字签名。还有就是每次签名都应选取不同的随机值来保证安全。

2. 实现

   因为整个过程是SM2体系下进行的，所以先是确定SM2椭圆曲线的参数以及原根G和G的阶n，转化为int方便后续计算。还有就是整个过程中所有计算只涉及了G的横坐标，所以为减少不必要计算我只计算了横坐标，竖坐标没有参与G的运算。在真实网络通信环境中实现，利用了套接字socket来实现TCP和UDP协议实现。为加强安全性，整个过程中采用加密传输，传输加密解密使用的RSA算法，填充方案选用的PKCS1_OAEP，所以为保证后续信息的正常加密，选用的是4096位的密钥，保证合法明密文长度足够大。RSA公私钥生成是在协议执行之前完成的，双方的公钥已经全部作为常量放到各自文件中了。过程中有一个计算哈希的步骤，我用的是SHA-256。整个过程中大部分是处理网络通信的代码，实现中间值计算的代码很少，全部是完全按照示意图中计算过程进行的，大部分都是进行监听端口和连接端口，有效代码全为途中流程代码，就不全部放到这里了，具体代码在Project-15文件中的SM2-sign-p2.py和SM2-sign-p1.py。下面用运行过程图展示效果。

   1. 双方开启各自服务，等待开始指令

      ![](D:\Desktop\创新创业实践\project15\Snipaste_2023-08-01_10-42-05.png)

   2. 开始之后，流程开始，为验证中间值是否传输正确以及展示流程是否完整，我把中间值都打印出来，以及端口连接和接受的数据也全都打印出来了。一次签名结束后，回到初始状态等待开始指令。

      ![](D:\Desktop\创新创业实践\project15\Snipaste_2023-08-01_11-27-12.png)

   3. 模拟真实功能，可以重复签名。

      ![](D:\Desktop\创新创业实践\project15\Snipaste_2023-08-01_11-32-26.png)

      

   4. 效率测试

      完成一次签名时间大约为1.1秒。

      但是我这是在我自己主机上不同端口之间的通信，和真实网络通信差距还是蛮大的。

      （一开始没写计时代码，所以上图中都没有时间显示，后面我为测试时间又加上了三句代码，上面的图片就没有修改。）

      ![](D:\Desktop\创新创业实践\project15\Snipaste_2023-08-01_15-35-16.png)

3. 环境

   CPU:

   ![](D:\Desktop\创新创业实践\project2\Snipaste_2023-07-20_22-43-35.png)

   软件:

   PyCharm Community Edition 2023.1.4

   

   

   

#### 2.16 - implement sm2 2P decrypt with real network communication

1. 原理

   SM2 two-party decrypt 过程图如下。实现的是SM2的解密过程，其实更像是明文恢复。把私钥分成了两个子密钥，两个子密钥可以计算出私钥，但是只有一个无法获得私钥。把解密过程分成两部分，两部分各自有一个子密钥，有效保护了私钥安全性。主要思想就是用不包含任何有关密钥明文信息的值计算出原本使用敏感信息计算出来的值，感觉就是殊途同归，只是换了一条隐藏了所有敏感信息的路来实现相同的目的。并且更进一步的是把能组合出敏感信息的值进一步拆分到了两部分，只有两部分各自交换自己知道的“毫无价值的”信息，才能得出明文。进一步提高了安全性。

   ![](D:\Desktop\创新创业实践\project16\Snipaste_2023-08-01_14-43-46.png)

2. 实现

   因为同样都是在SM2椭圆曲线基础上模拟真实网络通信实现的，所以这个的是实现和SM2 two-party sign几乎相同，只有中间值的计算步骤不同和交互的顺序不同。上个实现中因为不涉及竖坐标的运算所以我直接忽略了，但这次实现中需要竖坐标参与运算，所以这次是真正的椭圆曲线上的坐标运算。真实网络通信依旧是用的socket套接字。椭圆曲线参数、原根G以及G的阶n都和上个project一致。同样传输过程中使用的RSA算法，填充方案也是PKCS1_OAEP，密钥长度选取依旧是4096位，这个已经足够该协议进行传输数据了。各自的RSA公钥私钥是提前计算好直接放到脚本里的，因为现实中也是到一个可信第三方查找对应的公钥，我就相当于这个可信第三方直接放进去了。具体代码在Project-16文件中的SM2-decrypt-p2.py和SM2-decrypt-p1.py。下面还是用运行过程图展示效果。

   1. 初始状态，p2方监听自己端口接受数据，p1方询问是否开始。

      ![](D:\Desktop\创新创业实践\project16\Snipaste_2023-08-01_15-11-50.png)

   2. 开始后，按照流程图顺序依次传输中间值，最后p1根据p2计算出来的值和密文信息计算出明文，再加密看是否一致。为了检验流程是否正确，结果是否正确，我把初始随机选取的明文以及中间过程中端口的连接信息以及传输的中间值都打印出来了。当然，这些接收的信息都是进过解密后的原始数据，传输的密文我没有打印出来。加密解密过程是真实进行了的，代码中可以看到。

      ![](D:\Desktop\创新创业实践\project16\Snipaste_2023-08-01_15-15-20.png)

      

      效率测试：完成一次大约为0.8秒。

      因为这是在我自己的设备上运行的，不同的端口代表不同的设备，同台主机不同端口间的通信绝对比不同主机间不同端口间的通信更稳定更快速，所以不太有参考价值，但是也测试了（一开始没写时间函数，上面图中都没有时间，下面是我又添了计时代码后的运行结果）。完成一次时间大约为0.8秒。但是这是仅仅加密了32字节的明文，明文长度的增长也会增加时间开销，所以0.8秒这个值不太具有参考价值感觉。

      ![](D:\Desktop\创新创业实践\project16\Snipaste_2023-08-01_15-27-37.png)

      

3. 环境

   CPU:

   ![](D:\Desktop\创新创业实践\project2\Snipaste_2023-07-20_22-43-35.png)

   软件:

   PyCharm Community Edition 2023.1.4

   

   





#### 2.17 - 比较Firefox和谷歌的记住密码插件的实现区别

1. 简单比较

   为了比较这两个浏览器记住密码插件的实现区别，我先是下载了这两个浏览器注册账号然后添加了一两个密码。第一个不同，在第一次使用时Chrome提示我下载一个密码管理工具“Google password manager"，本来以为是需要在外部使用，但是再打开就直接打开了，应该是方便直接管理密码。第二个不同，打开密码工具后，Chrome只会显示对应保存的网址，其他信息都需要输入Pin码获得，而Firefox会直接显示出网址和对应的用户名。第三个不同，在显示密码时Chrome会触发Windows安全提示需要输入我的Pin码来显示，但是Firefox会直接显示出来。第四个不同，顶部地址栏中的信息不同，Chrome中就是管理工具的名称地址，而Firefox中存在一串十六进制字符串，不同的密码对应不同的串值，猜测是为显示对应密码信息用的参数，每组密码对应一个串值。

   然后在网络上搜索了一下差别，回答说是主要区别在于各自使用的API和存储密码的方式。

   API：

   Firefox通过“nsILoginManager”接口实现，提供了对登录信息的添加、删除、查找和更新登录信息等管理和存储功能。

   Chrome通过”chrome.identity“接口实现，提供保存和获取用户登入信息等对身份验证和授权的支持。

   存储：

   Firefox将登录信息存储在一个名为”logins.json“的文件中，该文件位于Firefox的配置文件夹中。

   Chrome将登录信息存储在一个名为“Login Data”的数据库中。

   

   Chrome:

   ![](D:\Desktop\创新创业实践\project17\Snipaste_2023-07-29_09-12-50.png)

   Firefox:

   ![Snipaste_2023-07-29_09-13-17](D:\Desktop\创新创业实践\project17\Snipaste_2023-07-29_09-13-17.png)

2. 源码比较

   下载源码

   Chrome

   ![](D:\Desktop\创新创业实践\project17\Snipaste_2023-07-29_10-33-44.png)

   Firefox

   ![Snipaste_2023-07-29_10-33-53](D:\Desktop\创新创业实践\project17\Snipaste_2023-07-29_10-33-53.png)

   找到对应的文件

   Firefox

   ![](D:\Desktop\创新创业实践\project17\Snipaste_2023-07-29_10-42-19.png)

   Chrome

   ![](D:\Desktop\创新创业实践\project17\Snipaste_2023-07-29_10-42-57.png)

   

   

   

   

#### 2.18 - send a tx on Bitcoin testnet, and parse the tx data down to every bit

1. 发送交易

   我使用的本地搭建Bitcoin Core来进行接收发送交易，首先是下载Bitcoin Core：

   ![](D:\Desktop\创新创业实践\project18\Snipaste_2023-07-27_17-44-29.png)

   之后安装完成后打开会提示会下载从2009开始的完整的区块链，大约是420G，这是真正的Bitcoin的主网络。在这个上面进行交易用的是真正的比特币，大可不必。所以需要先要将主网络修改为Bitcoin的测试网络，修改方法是更改Bitcoin Core的配置文件添加“testnet =1”语句，之后重启Bitcoin Core就切换到测试网络了。切换成功后会自动同步测试网络，整个数据大约为33GB。同步完成后就可以正常使用了。之后为了正常使用需要先创建一个钱包，我这个叫“fxy”。

   ![](D:\Desktop\创新创业实践\project18\Snipaste_2023-07-27_17-51-12.png)

   ![](D:\Desktop\创新创业实践\project18\Snipaste_2023-07-27_17-52-36.png)

   之后为发送一笔交易，先要获得一笔比特币，首先是创建自己的收款地址，在接收中新建收款地址：

   ![](D:\Desktop\创新创业实践\project18\Snipaste_2023-07-27_17-54-41.png)

   然后去网上找一个水龙头网站给这个咱生成的地址发送一些测试比特币：

   ![](D:\Desktop\创新创业实践\project18\Snipaste_2023-07-27_17-57-07.png)

   这样Bitcoin Core就会接收这些测试比特币，测试网络和主网络一样需要经过几次确认才可以正常使用，大约等待十几分钟就行了。之后等已经确认完成后，即可使用余额不为零就可以发送交易了。只需要在发送中输入金额等信息然后确认签名发送就完成了。发送之后点击这笔交易就可以看到详细信息，如下：

   ![](D:\Desktop\创新创业实践\project18\Snipaste_2023-07-27_18-05-03.png)

   之后为了得到更详细的数据可以到特定网站解析交易ID，如下：

   ![](D:\Desktop\创新创业实践\project18\Snipaste_2023-07-27_18-06-51.png)

2. 解析数据

   我这笔交易的ID为1aadced53489d100acaa9dca551fc710ebd8c43733b9ba776220dec781bfaab5。在上面这个网站可以看到该笔交易的Hex值：

   ![](D:\Desktop\创新创业实践\project18\Snipaste_2023-07-27_18-24-50.png)

   之后该网站下可以直接转换该Hex，结果如下：

   ```
   {
       "addresses": [
           "tb1q5kcnmg78yv7zrvhu7843z8yj9glmv7mz6hlz8d",
           "tb1q7w4pkc4u3ls2rk4kejxvpv65qmt94u8qqwk86j",
           "tb1qw2c3lxufxqe2x9s4rdzh65tpf4d7fssjgh8nv6",
           "tb1qhlhucut59pdhwdnz5uym7y5uuscfyhyh48wegg"
       ],
       "block_height": -1,
       "block_index": -1,
       "confirmations": 0,
       "double_spend": false,
       "fees": 313,
       "hash": "1aadced53489d100acaa9dca551fc710ebd8c43733b9ba776220dec781bfaab5",
       "inputs": [
           {
               "addresses": [
                   "tb1qhlhucut59pdhwdnz5uym7y5uuscfyhyh48wegg"
               ],
               "age": 2468585,
               "output_index": 0,
               "output_value": 1000,
               "prev_hash": "54c73960d12b4871312fba2c58517defd5a1de396a3dad7c8aac3df7b3ca05d2",
               "script_type": "pay-to-witness-pubkey-hash",
               "sequence": 4294967293,
               "witness": [
                   "304402205214f14fb41dd8bdd824a5b38860d91c772b5d833928c7fd7d251876c539d37b022023250c2dcf38205ba71b0f83009a37f5e08bb23b55493e9fd48dd1e85b102a1c01",
                   "036a66aca48601f3d0161ac59f6f9b54a148d23078ce6157b17fdb3f20ea51bdff"
               ]
           },
           {
               "addresses": [
                   "tb1q5kcnmg78yv7zrvhu7843z8yj9glmv7mz6hlz8d"
               ],
               "age": 2468584,
               "output_index": 1,
               "output_value": 1000,
               "prev_hash": "dc44760815d094cc8a9021d3c69c5d99429f619a1087c6afaf9a1c6916cb8aa0",
               "script_type": "pay-to-witness-pubkey-hash",
               "sequence": 4294967293,
               "witness": [
                   "304402201c9abae972c64d72e01ba7b6990c1f41d594c8779674e75095620fe82d898b900220329c8971a2b4ccde602ef1e506d463ce356ec93e17aaf1e791a0988b06b21aaa01",
                   "032fe79d9839e4cc768f95b60913322bf38ffcf66ef071777ca16b1617ea657aef"
               ]
           },
           {
               "addresses": [
                   "tb1q7w4pkc4u3ls2rk4kejxvpv65qmt94u8qqwk86j"
               ],
               "age": 2468585,
               "output_index": 1,
               "output_value": 7344,
               "prev_hash": "e96dc94bebcb88387bb025c733cdcb46b63e987673e3578937ad041c480bc8f1",
               "script_type": "pay-to-witness-pubkey-hash",
               "sequence": 4294967293,
               "witness": [
                   "304402204b679b74c1d72a29bcc24aa37e90d59b16cad5c2d3dafe8557766ebb0316e0c30220746d3c2cfe0d3e3f2088b260c6f73efa0e28928ea08248eee3424172597b15b701",
                   "03012e16ac21389bb7b8967ff868c2f412818108325d3cab3e3909db692562a12f"
               ]
           },
           {
               "addresses": [
                   "tb1q7w4pkc4u3ls2rk4kejxvpv65qmt94u8qqwk86j"
               ],
               "age": 2468585,
               "output_index": 0,
               "output_value": 1000,
               "prev_hash": "2ad5a8c0cccd1868d74ac3e6f421991920e339db2f96bb80bc5f2b09a5d4a54b",
               "script_type": "pay-to-witness-pubkey-hash",
               "sequence": 4294967293,
               "witness": [
                   "3044022077e79a69730ffe5e907b104c2c0c837c27a1eeabc1acf42c94c9b561668d7160022046ec4088410e38bef2b89e9c5ab05b4c6d2f6d003469b3779d5e1ad32ce16da901",
                   "03012e16ac21389bb7b8967ff868c2f412818108325d3cab3e3909db692562a12f"
               ]
           }
       ],
       "lock_time": 2468676,
       "opt_in_rbf": true,
       "outputs": [
           {
               "addresses": [
                   "tb1qw2c3lxufxqe2x9s4rdzh65tpf4d7fssjgh8nv6"
               ],
               "script": "001472b11f9b893032a316151b457d51614d5be4c212",
               "script_type": "pay-to-witness-pubkey-hash",
               "value": 10031
           }
       ],
       "preference": "low",
       "received": "2023-07-27T10:23:11.105990444Z",
       "relayed_by": "54.86.77.44",
       "size": 635,
       "total": 10031,
       "ver": 2,
       "vin_sz": 4,
       "vout_sz": 1,
       "vsize": 313
   }
   ```

   

3. 实现环境

   CPU:

   ![](D:\Desktop\创新创业实践\project2\Snipaste_2023-07-20_22-43-35.png)

   所用网站：

   Bitcoin Core:https://bitcoin.org/zh_CN/download

   Bitcoin 水龙头:https://bitcoinfaucet.uo1.net/send.php

   交易信息:https://live.blockcypher.com/btc-testnet/

   交易详细信息:https://live.blockcypher.com/btc-testnet/decodetx/

   

   

#### 2.19 - forge a signature to pretend that you are Satoshi

1. 背景和原理

   ![](D:\Desktop\创新创业实践\project19\Snipaste_2023-08-03_16-07-08.png)

   有人发布了消息的哈希值和对应的签名，想借此证明自己是中本聪。对于这个消息哈希来说，签名值是有效的。但是因为没有发布消息哈希对应的消息，不知道签名的消息是否是有意义的，如果是有意义的，那么有可能确实是中本聪本人，但是如果是无意义的消息值，那么就无法确认是否是中本聪了。出现这种情况是因为比特币中使用的ECDSA签名算法，是可以伪造出有效的签名的，但是所对应的消息就不一定是有意义的了。伪造过程如下图Pieter Wuille推文中描述的那样。如果在伪造时使用的是创世区块的公钥P，那么生成出来的伪造签名和伪造消息就“证明”了我是中本聪。因为在无法伪造的情况下，能生成有效签名必须有私钥值，而私钥值在比特币中可以说就是一个的代表凭证。

   ![](D:\Desktop\创新创业实践\project19\Snipaste_2023-08-03_17-11-05.png)

2. 实现

   首先是选取两个随机值u和v，根据R = uG+vP，r = R.x，让s = r/v，z = us，这样之后（r，s），z就是一个有效的签名了。在代码实现中，首先是根据以上步骤进行伪造，然后通过签名验证函数检查是否是有效的。代码中使用的是ecc库。公钥值使用的是创世区块的公钥值，所以生成出来的伪造签名和伪造消息可以“证明”我是中本聪。

   代码实现：

   ```python
   def test():
       GENESIS_BLOCK_PUBKEY = '04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f'
       point = S256Point.parse(bytes.fromhex(GENESIS_BLOCK_PUBKEY))
       u = randint(0, N)
       v = randint(0, N)
       r = (u * G + v * point).x.num % N
       s = r * pow(v, N - 2, N) % N
       z = u * s % N
       sig = Signature(r, s)
       assert point.verify(z, sig) is True
       print("消息哈希值 : ", z)
       print('签名值 :', sig)
   ```

   运行结果：

   ![](D:\Desktop\创新创业实践\project19\Snipaste_2023-08-03_21-07-01.png)

3. 环境

   CPU:

   ![](D:\Desktop\创新创业实践\project2\Snipaste_2023-07-20_22-43-35.png)

   软件:

   PyCharm Community Edition 2023.1.4

4. 参考文章：

   https://jimmysong.medium.com/faketoshis-nonsense-signature-8700a44536b5

   https://bitcoin.stackexchange.com/questions/81115/if-someone-wanted-to-pretend-to-be-satoshi-by-posting-a-fake-signature-to-defrau

   

   



#### 2.20 - Schnorr Bacth

1. 原理

   Schnorr Batch是一种基于Schnorr签名的批量签名方案，可以在一次计算中对多个消息进行签名，从而提高签名效率和降低交易费用。它是在保证安全性的前提下实现批量签名的一种方案。核心思想是将多个消息的哈希值相加，得到一个新的哈希值，并根据这个哈希值进行一次Schnorr签名，从而实现对多个消息的批量签名。通过Schnorr Batch可以在一次计算中对多个消息进行签名提高签名效率和降低交易费用；与单个Schnorr签名一样具有较强的安全性，可以抵御各种攻击；可以与隔离见证（SegWit）等技术结合使用，进一步提高交易效率和降低交易费用。

2. 实现

   Schnorr Batch是基于Schnorr签名算法实现的，所以为实现Schnorr Batch首先需要实现Schnorr签名算法，然后根据Schnorr签名实现Schnorr Batch。

   1. Schnorr签名算法

      ![](D:\Desktop\创新创业实践\project20\Snipaste_2023-08-03_10-16-51.png)

      Schnorr签名算法的两种版本。这里选取的是左边这一版本，因为我看下面的Schnorr Batch签名描述是使用这一版本。

      ```python
      def schnorr_sign(m, x):
          k = random.randint(1, n-1)
          R = (k * Gx, k * Gy)
          e = int(hashlib.sha256(str(R[0]).encode() + m).hexdigest(), 16)
          s = (k + x * e) % n
          return R, s
      ```

      

   2. Schnorr Batch签名验证

      批量验证利用的是Schnorr签名的线性特征，多个签名值的相加就可以组合成一个合法的签名值。中间实现过程中需要注意结算结果都要模掉n，如果不模n最终显示结果不正确。

      ![](D:\Desktop\创新创业实践\project20\Snipaste_2023-08-03_10-31-34.png)

      ```python
      def schnorr_batch_verification(msg_list, x):
          r_0 = 0
          r_1 = 0
          e_0 = 0
          e_1 = 0
          ss = 0
          for msg in msg_list:
              r, s = schnorr_sign(msg.encode(), x)
              e = int(hashlib.sha256(str(r[0]).encode() + msg.encode()).hexdigest(), 16)
              e_0 += e * x * Gx
              e_1 += e * x * Gy
              ss += s
              r_0 += r[0]
              r_1 += r[1]
          E = (e_0 % n, e_1 % n)
          R = (r_0 % n, r_1 % n)
          S = ss % n
          a = (S * Gx % n, S * Gy % n)
          print(a)
          b = ((R[0] + E[0]) % n, (R[1] + E[1]) % n)
          print(b)
          if a == b:
              print('success')
          return R, S
      ```

   测试结果：

   成功实现，签名验证通过。下面是我打印出来的中间值。

   ![](D:\Desktop\创新创业实践\project20\Snipaste_2023-08-03_11-33-37.png)

3. 环境

   CPU:

   ![](D:\Desktop\创新创业实践\project2\Snipaste_2023-07-20_22-43-35.png)

   软件:

   PyCharm Community Edition 2023.1.4

   

   

   

#### 2.21 - research report on MPT



​																				Merkle Patricia Tree（MPT）研究报告

一、摘要

​		Merkle Patricia Tree（又称为Merkle Patricia Trie），下面简称为MPT，是一种经过改良的、融合了Merkle tree和前缀树两种树结构优点的数据结构，是以太坊中用来组织管理账户数据、生成交易集合哈希的重要数据结构。主要作用有存储任意长度的键值对数据、提供快速计算所维护数据集哈希标识机制、提供快速回滚机制以及提供Merkle证明的证明方法进行轻节点扩展并实现简单支付验证等功能。本文目的是了解、实现并掌握Merkle Patricia Tree。研究方法为网络搜索资料和自己本地代码实现测试。经过本次研究了解，熟悉了MPT的设计原理、数据结构和实现方法，同时也更加熟悉了解了哈希函数、Merkle树和前缀树等MPT的相关技术。

二、引言

​		MPT的历史可以追溯到2014年，当时以太坊创始人Vitalik Buterin提出这种数据结构，并在以太坊的设计中被广泛采用。目前，MPT数据结构已经成为区块链领域的一个重要研究方向。许多研究人员正在努力探索如何进一步优化MPT算法，提高其性能和安全性。同时，MPT也被广泛应用于各种区块链应用场景，如数字货币、智能合约等领域。通过本次研究，可以了解MPT、前缀树等重要数据结构，同时也更加熟悉了哈希函数和Merkle树等概念。本文主要研究内容包括MPT相关技术、MPT设计实现、MPT性能和安全性分析三部分。

三、MPT相关技术

​		MPT的设计实现中涉及许多相关技术和概念，主要包括哈希函数、Merkle树、前缀树、Patricia Trie、Radix Tree等。这些技术在和概念在MPT中扮演者重要的角色，共同作用下构建了MPT这种高效、可扩展和安全的数据结构。下面会简要介绍上述几种技术。

- 哈希函数：哈希函数是将任意长度的输入数据映射为固定长度输出的函数。在MPT中，哈希函数被广泛应用于计算数据的哈希值，以及构建Merkle树等数据结构。
- Merkle树：梅克尔树是一种用于验证数据完整性的树形数据结构。在MPT中，梅克尔树被用于存储和验证数据的哈希值，以及计算数据的根哈希值。
- 前缀树：前缀树是一种用于存储和查询字符串的数据结构。在MPT中，前缀树被用于存储和查询键值对数据，以及实现快速的数据访问和更新。
- Patricia Trie：一种压缩Trie树，它将具有相同前缀的字符串合并为一个节点，从而减少了存储空间和查询时间。Patricia Trie的名称来自于其发明者Donald R. Morrison的女儿Patricia。在MPT中，Patricia Trie被用于存储和查询键值对数据的前缀，从而实现快速的数据访问和更新。
- Radix Tree：一种压缩Trie树，它将具有相同前缀的字符串合并为一个节点，并且还将不必要的节点进行合并，从而进一步减少了存储空间和查询时间。在MPT中，Radix Tree被用于存储和查询键值对数据的后缀，从而实现快速的数据访问和更新。

四、MPT设计实现与功能

​		这一部分首先是介绍MPT的设计原理、数据结构和实现方法，然后会介绍MPT实现的功能。

- 设计原理、数据结构和实现方法

  - 设计原理

    MPT的设计原理是将键值对数据存储在一个树形结构中，其中每个节点都包含一个键和一个值。MPT通过将相同前缀的键合并为一个节点，从而减少了存储空间和查询时间。同时，MPT还使用了梅克尔树和哈希函数来保证数据的完整性和安全性。

  - 数据结构

    MPT的数据结构由四种节点类型组成，分别是叶子节点、扩展节点、空节点和分支节点。其中，叶子节点存储键值对数据，扩展节点存储键的前缀，空节点表示不存在的节点，分支节点存储多个子节点的哈希值。

  - 实现方法

    MPT的实现方法是通过递归遍历树来实现数据的访问和更新。当需要查询或更新某个键值对数据时，MPT会从根节点开始递归遍历树，直到找到对应的叶子节点。在遍历过程中，MPT会使用哈希函数计算每个节点的哈希值，并将其存储在父节点中。当需要验证数据完整性时，MPT会使用梅克尔树和哈希函数来计算根节点的哈希值，并将其与预期的哈希值进行比较。

- 实现功能

  - 快速计算所维护数据集哈希标识

    这个特点体现在单节点计算的第一步，即在节点哈希计算之前会对该节点的状态进行判断，只有当该节点的内容变脏，才会进行哈希重计算、数据库持久化等操作。如此一来，在某一次事务操作中，对整棵MPT树的部分节点的内容产生了修改，那么一次哈希重计算，仅需对这些被修改的节点、以及从这些节点到根节点路径上的节点进行重计算，便能重新获得整棵树的新哈希。

  - 快速状态回滚

    在公链的环境下，采用POW算法是可能会造成分叉而导致区块链状态进行回滚的。在以太坊中，由于出块时间短，这种分叉的几率很大，区块链状态回滚的现象很频繁。

    所谓的状态回滚指的是：（1）区块链内容发生了重组织，链头发生切换（2）区块链的世界状态（账户信息）需要进行回滚，即对之前的操作进行撤销。

    MPT树就提供了一种机制，可以当区块碰撞发生了，零延迟地完成世界状态的回滚。这种优势的代价就是需要浪费存储空间去冗余地存储每个节点的历史状态。

    每个节点在数据库中的存储都是值驱动的。当一个节点的内容发生了变化，其哈希相应改变，而MPT将哈希作为数据库中的索引，也就实现了对于每一个值，在数据库中都有一条确定的记录。而MPT是根据节点哈希来关联父子节点的，因此每当一个节点的内容发生变化，最终对于父节点来说，改变的只是一个哈希索引值；父节点的内容也由此改变，产生了一个新的父节点，递归地将这种影响传递到根节点。最终，一次改变对应创建了一条从被改节点到根节点的新路径，而旧节点依然可以根据旧根节点通过旧路径访问得到。

  - 使用默克尔证明能够实现轻节点的扩展

    在以太坊或比特币中，一个参与共识的全节点通常会维护整个区块链的数据，每个区块中的区块头信息，所有的交易，回执信息等。由于区块链的不可篡改性，这将导致随着时间的增加，整个区块链的数据体量会非常庞大。运行在个人PC或者移动终端的可能性显得微乎其微。为了解决这个问题，一种轻量级的，只存储区块头部信息的节点被提出。这种节点只需要维护链中所有的区块头信息。在公链的环境下，仅仅通过本地所维护的区块头信息，轻节点就能够证明某一笔交易是否存在与区块链中；某一个账户是否存在与区块链中，其余额是多少等功能。默克尔证明指一个轻节点向一个全节点发起一次证明请求，询问全节点完整的默克尔树中，是否存在一个指定的节点；全节点向轻节点返回一个默克尔证明路径，由轻节点进行计算，验证存在性。

五、MPT性能和安全性分析

​		性能：

- [ ] 存储效率高：MPT使用前缀压缩技术，可以将相似的键值对共享前缀，从而节省存储空间。

- [ ] 检索效率高：MPT使用哈希值来索引数据，可以快速地查找和检索数据。

- [ ] 可扩展性好：MPT支持动态添加和删除键值对，具有很好的可扩展性。

  安全性：

- [ ] 不可篡改：MPT使用哈希值来保证数据的完整性，任何对数据的篡改都会导致哈希值不匹配，从而被检测到。

- [ ] 防止重放攻击：MPT使用随机数和时间戳来防止重放攻击，保证了数据的安全性。

- [ ] 隐私保护：MPT使用前缀压缩技术和哈希值来加密数据，保护了用户的隐私。

六、总结

​		Merkle Patricia Trie（MPT）是一种高效、安全的数据结构，它结合了Merkle树和前缀树的优点。MPT最初是为以太坊区块链设计的，用于存储和检索交易数据。随着区块链技术的发展，MPT也被广泛应用于其他领域。MPT的主要特点是存储效率高、检索效率高、可扩展性好和安全性高。MPT使用前缀压缩技术和哈希值来节省存储空间，并使用哈希值来索引数据，可以快速地查找和检索数据。MPT支持动态添加和删除键值对，具有很好的可扩展性。MPT使用哈希值来保证数据的完整性，任何对数据的篡改都会导致哈希值不匹配，从而被检测到。MPT还使用随机数和时间戳来防止重放攻击，保证了数据的安全性。在实际应用中，MPT已经被广泛应用于区块链技术、分布式存储、分布式数据库等领域。例如，以太坊区块链使用MPT来存储交易数据，IPFS分布式存储系统使用MPT来存储文件元数据。此外，MPT还可以用于构建分布式DNS系统、分布式身份验证系统等。总之，Merkle Patricia Trie是一种高效、安全、可扩展的数据结构，具有广泛的应用前景。随着区块链技术和分布式系统的发展，MPT将会发挥越来越重要的作用。
