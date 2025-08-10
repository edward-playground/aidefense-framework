// 導入介紹內容
import { aidefendIntroduction } from './intro.js';

// 導入所有拆分的 tactics
import { modelTactic } from './tactics/model.js';
import { hardenTactic } from './tactics/harden.js';
import { detectTactic } from './tactics/detect.js';
import { isolateTactic } from './tactics/isolate.js';
import { deceiveTactic } from './tactics/deceive.js';
import { evictTactic } from './tactics/evict.js';
import { restoreTactic } from './tactics/restore.js';

// 重新組合回原始的 aidefendData 物件
export const aidefendData = {
    "introduction": aidefendIntroduction,
    "tactics": [
        modelTactic,
        hardenTactic,
        detectTactic,
        isolateTactic,
        deceiveTactic,
        evictTactic,
        restoreTactic
    ]
};

// 預設將 aidefendData 匯出 以供其他模組使用
export default aidefendData;