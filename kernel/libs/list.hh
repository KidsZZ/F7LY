// linked_list.hh
#pragma once

#include <cstddef>

template <typename T>
class LinkedList {
private:
    struct Node {
        Node* next;
        Node* prev;
        T data;

        Node() : next(nullptr), prev(nullptr) {}
        explicit Node(const T& value) : next(nullptr), prev(nullptr), data(value) {}
    };

    Node* head;
    size_t size;

public:
    // 构造函数
    LinkedList() : head(new Node()), size(0) {
        head->next = head;
        head->prev = head;
    }

    // 析构函数
    ~LinkedList() {
        clear();
        delete head;
    }

    // 访问第一个元素
    T& front() {
        return head->next->data;
    }

    const T& front() const {
        return head->next->data;
    }

    // 在头部插入元素
    void push_front(const T& value) {
        Node* newNode = new Node(value);
        newNode->next = head->next;
        newNode->prev = head;
        head->next->prev = newNode;
        head->next = newNode;
        size++;
    }

    // 删除头部元素
    void pop_front() {
        if (!empty()) {
            Node* toDelete = head->next;
            head->next = toDelete->next;
            toDelete->next->prev = head;
            delete toDelete;
            size--;
        }
    }

    // 判断是否为空
    bool empty() const {
        return size == 0;
    }

    // 获取大小
    size_t get_size() const {
        return size;
    }

    // 清空链表
    void clear() {
        while (!empty()) {
            pop_front();
        }
    }

    // 迭代器类
    class Iterator {
    private:
        Node* current;

    public:
        explicit Iterator(Node* node) : current(node) {}

        T& operator*() {
            return current->data;
        }

        Iterator& operator++() {
            current = current->next;
            return *this;
        }

        Iterator operator++(int) {
            Iterator temp = *this;
            current = current->next;
            return temp;
        }

        bool operator==(const Iterator& other) const {
            return current == other.current;
        }

        bool operator!=(const Iterator& other) const {
            return !(*this == other);
        }

        Node* get_node() const { return current; }
    };

    // 删除元素
    Iterator erase(Iterator pos) {
        if (pos == end()) return pos;
        
        Node* toDelete = pos.get_node();
        Iterator next(toDelete->next);
        
        toDelete->prev->next = toDelete->next;
        toDelete->next->prev = toDelete->prev;
        delete toDelete;
        size--;
        
        return next;
    }

    // 获取开始迭代器
    Iterator begin() {
        return Iterator(head->next);
    }

    // 获取结束迭代器
    Iterator end() {
        return Iterator(head);
    }
};