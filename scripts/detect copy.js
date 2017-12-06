const domainRegsObj = {
    'google.com': {
        aPartn: /aaaa/,
        bPartn: /bbb/},
    'facebook.com': {
        aPartn: /aaaa/,
        bPartn: /bbb/}
    };

            // 判断函数
            function isCode(domain, str) {
                // 对应域名所有的正则
                var domainRegs = domainRegsObj[domain];
                // 所有配置到正则的值的数组
                var matchs = {};

                // 遍历正则
                Object.keys(domainRegs).map(function (key) {
                    const partn = domainRegs[key];
                    // 把匹配到的值保存起来,key为正则的key
                    matchs[key] = str.match(partn);
                });
                return matchs;
            }

            const matchs = isCode('facebook.com', 'aaaa');

            // 如配置到a
            if (matchs.aPartn) {

            }
            // 如匹配到b
            if (matchs.bPartn) {

            }
