# BinMatch

A binary vulnerable function detection tool powered by angr

## Install angr

Please follow [angr installation guide](https://docs.angr.io/introductory-errata/install)

Command used

```
https://docs.angr.io/introductory-errata/install
mkvirtualenv --python=$(which python3) angr && pip install angr
workon angr
deactivate
```

I encountered some path problem with virtualenv when trying to run `mkvirtualenv`, and fixed by the following method

* https://stackoverflow.com/questions/29149853/no-module-named-virtualenvwrapper
* ```
    export VIRTUALENVWRAPPER_PYTHON=/usr/bin/python3
    python3 -m pip install virtualenvwrapper
    ```

## Usage

Secify names of vulnerable functions to detect in conf.yaml first

Then

```
python3 BinDiff.py conf.yaml target_lib target_firmware
```

# Notes  

## angr.analyses.bindiff.FunctionDiff

### Algorithm Analysis

#### Part 1

Try to use block attributes to match blocks in two function first

**block attributes**

* _distances_from_function_start
  *  A dictionary of basic block addresses and their distance(single_source_shortest_path) to the start of the function.
* _distances_from_function_exit
  * A dictionary of basic block addresses and their distance(single_source_shortest_path) to the exit of the function.
* number_of_subfunction_calls
  * number of call sites
  * The block normalization includes a block merge operation(merge if a block ends with a single call, and the successor has only one predecessor and succ is after), so a basic block might have multiple call sites

**_get_closest_matches**

For each block in function A and function B, use euclidean distance to find blocks with closest attributes

* O(n^2)
* dictionary {block -> list of blocks(matched block list)}



#### Part 2

If multiple blocks have the same attributes distance to a block, then **block similarity** can be evaluated to break this tie 

**block_similarity**

Is this a bug?

```python
            if n.addr in self.merged_blocks:
                for block in self.merged_blocks[n]:
                    if block.addr in self.orig_function.get_call_sites():
                        call_targets.append(self.orig_function.get_call_target(block.addr))
```

NormalizedBlock

* Find all the subblocks for each merged block(after Function Normalize), get the IR(VEX) of each subblock, then extract some information(statements, constants, operations, jumpkind) from IR

Get summary for each block

* list of tags (tag for every statement in VEX)
* list of constants (value of each constant)
* list of all registers used (register offset in VEX)
* jumpkind (jump type?)

Levenshtein distance between these two summaries is calculated

A modification for Levenshtein distance is also calculated

```python
_get_acceptable_constant_differences
# Seek for possible differences between constants and put them into a set, this values in this set are considered as "zero" in normalized levenshtein distance calculation 
_normalized_levenshtein_distance
```

Total distance between two blocks

```
total_dist = 0
total_dist += _levenshtein_distance(tags_a, tags_b)
total_dist += _levenshtein_distance(block_a.operations, block_b.operations)
total_dist += _levenshtein_distance(all_registers_a, all_registers_b)
acceptable_differences = self._get_acceptable_constant_differences(block_a, block_b)
total_dist += _normalized_levenshtein_distance(consts_a, consts_b, acceptable_differences)
total_dist += 0 if jumpkind_a == jumpkind_b else 1
```

Block similarity

```
num_values = max(len(tags_a), len(tags_b))
num_values += max(len(consts_a), len(consts_b))
num_values += max(len(block_a.operations), len(block_b.operations))
num_values += 1  # jumpkind
similarity = 1 - (float(total_dist) / num_values)
```

Then we find blocks with the highest similarity for each block, and use this information to shrink the **matched blocks list** obtained in **Step 1**.

Then we traverse the blocks again. If two blocks, we name them as block A and block B, both only have the other block in their own matched block list, that is, A only match B, and B only match A, then we append this block pair to the **initial block matches**.

We observed that the matches above didn't take the graph structure(connection relationship) of CFG into account, that's what we are heading for next.



#### Part 3

The core function of this algorithm

```python
    def _compute_diff(self):
        """
        Computes the diff of the functions and saves the result.
        """
        # get the attributes for all blocks
        l.debug("Computing diff of functions: %s, %s",
                ("%#x" % self._function_a.startpoint.addr) if self._function_a.startpoint is not None else "None",
                ("%#x" % self._function_b.startpoint.addr) if self._function_b.startpoint is not None else "None"
                )
        self.attributes_a = self._compute_block_attributes(self._function_a)
        self.attributes_b = self._compute_block_attributes(self._function_b)

        # get the initial matches
        # 这里_get_block_matches没有用similarity来break tie
        initial_matches = self._get_block_matches(self.attributes_a, self.attributes_b,
                                                  tiebreak_with_block_similarity=False)

        # Use a queue so we process matches in the order that they are found
        to_process = deque(initial_matches)

        # Keep track of which matches we've already added to the queue
        # 记录已经处理过的match，确保后续循环是可结束的
        processed_matches = set((x, y) for (x, y) in initial_matches)

        # Keep a dict of current matches, which will be updated if better matches are found
        matched_a = dict()
        matched_b = dict()
        for (x, y) in processed_matches:
            matched_a[x] = y
            matched_b[y] = x

        # while queue is not empty
        # 这个循环就是个打擂台的过程
        while to_process:
            (block_a, block_b) = to_process.pop()
            l.debug("FunctionDiff: Processing (%#x, %#x)", block_a.addr, block_b.addr)

            # we could find new matches in the successors or predecessors of functions
            block_a_succ = list(self._function_a.graph.successors(block_a))
            block_b_succ = list(self._function_b.graph.successors(block_b))
            block_a_pred = list(self._function_a.graph.predecessors(block_a))
            block_b_pred = list(self._function_b.graph.predecessors(block_b))

            # propagate the difference in blocks as delta
            # 其实我不是很懂这个delta的意义，因为在_get_block_matches函数中function a和function b的block的attributes都加上了这个delta，这样
            # 看来岂不是等于没加？
            delta = tuple((i-j) for i, j in zip(self.attributes_b[block_b], self.attributes_a[block_a]))

            # get possible new matches
            new_matches = []

            # if the blocks are identical then the successors should most likely be matched in the same order
            # 如果两个block完全相同的话，那么他们的successors很可能是以完全相同的顺序(地址序)存在graph中的，而且对应block很可能会匹配，那么加入
            # new_match list中，等待进一步验证(打擂台)
            if self.blocks_probably_identical(block_a, block_b) and len(block_a_succ) == len(block_b_succ):
                ordered_succ_a = self._get_ordered_successors(self._project_a, block_a, block_a_succ)
                ordered_succ_b = self._get_ordered_successors(self._project_b, block_b, block_b_succ)
                new_matches.extend(zip(ordered_succ_a, ordered_succ_b))

            # 直接分别暴力遍历successors和precessors得出一些可能的match，加入new_match list
            # 注意，这里用到了similarity来break tie
            new_matches += self._get_block_matches(self.attributes_a, self.attributes_b, block_a_succ, block_b_succ,
                                                   delta, tiebreak_with_block_similarity=True)
            new_matches += self._get_block_matches(self.attributes_a, self.attributes_b, block_a_pred, block_b_pred,
                                                   delta, tiebreak_with_block_similarity=True)

            # for each of the possible new matches add it if it improves the matching
            for (x, y) in new_matches:
                if (x, y) not in processed_matches:
                    processed_matches.add((x, y))
                    l.debug("FunctionDiff: checking if (%#x, %#x) is better", x.addr, y.addr)
                    # if it's a better match than what we already have use it
                    # 不是很懂_is_better_match函数中为什么没有用similarity，而仅仅用了attributes，是为了把寄存器分配方案、constant之类的信息
                    # 排除在外?
                    if _is_better_match(x, y, matched_a, matched_b, self.attributes_a, self.attributes_b):
                        l.debug("FunctionDiff: adding possible match (%#x, %#x)", x.addr, y.addr)
                        if x in matched_a:
                            old_match = matched_a[x]
                            del matched_b[old_match]
                        if y in matched_b:
                            old_match = matched_b[y]
                            del matched_a[old_match]
                        matched_a[x] = y
                        matched_b[y] = x
                        to_process.appendleft((x, y))

        # reformat matches into a set of pairs
        self._block_matches = set((x, y) for (x, y) in matched_a.items())

        # get the unmatched blocks
        self._unmatched_blocks_from_a = set(x for x in self._function_a.graph.nodes() if x not in matched_a)
        self._unmatched_blocks_from_b = set(x for x in self._function_b.graph.nodes() if x not in matched_b)
```



## Note2

irsb = block.vex 

self.statements += irsb.statements

self.operations += irsb.operations

```
Load Memory
The value stored at a memory address, with the address specified by another IR Expression.
LDle:I32 / LDbe:I64

Store Memory
Update a location in memory, given as an IR Expression, with a value, also given as an IR Expression.
STle(0x1000) = (IR Expression)
```

```python
    @staticmethod
    def _get_ordered_successors(project, block, succ):
        try:
            # add them in order of the vex
            addr = block.addr
            succ = set(succ)
            ordered_succ = []
            bl = project.factory.block(addr)
            # 不是很懂这里，为什么succ中会有constant
            for x in bl.vex.all_constants:
                if x in succ:
                    ordered_succ.append(x)
			
            # add the rest (sorting might be better than no order)
            for s in sorted(succ - set(ordered_succ), key=lambda x:x.addr):
                ordered_succ.append(s)
            return ordered_succ
        except (SimMemoryError, SimEngineError):
            return sorted(succ, key=lambda x:x.addr)
```

_is_better_match函数中为什么没有用similarity













 