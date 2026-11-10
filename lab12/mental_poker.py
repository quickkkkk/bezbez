"""Демонстрационная раздача Texas Hold'em через последовательное шифрование колоды."""
from __future__ import annotations
import secrets, tkinter as tk
from tkinter import messagebox, simpledialog

PRIME=2**127-1
SUITS=('♠','♥','♦','♣'); RANKS=('2','3','4','5','6','7','8','9','10','J','Q','K','A')

def card_name(card:int)->str:return RANKS[card%13]+SUITS[card//13]
def make_layer(deck:list[int])->tuple[int,int]:
    # Степень обратима по длине группы; карты шифруются независимыми слоями игроков.
    while True:
        e=secrets.randbelow(PRIME-3)+2
        if __import__('math').gcd(e,PRIME-1)==1:break
    return e,pow(e,-1,PRIME-1)
def encrypt(card:int,e:int)->int:return pow(card+1,e,PRIME)
def remove_layer(card:int,d:int)->int:return pow(card,d,PRIME)
def shuffle(deck:list[int])->list[int]:
    deck=deck[:]
    for i in range(len(deck)-1,0,-1):
        j=secrets.randbelow(i+1);deck[i],deck[j]=deck[j],deck[i]
    return deck

class PokerApp:
    def __init__(self,root:tk.Tk)->None:
        self.root=root;root.title('Ментальный покер — Texas Hold’em');root.geometry('760x520')
        self.top=tk.Label(root,text='Ментальный покер',font=('Arial',20,'bold'));self.top.pack(pady=12)
        self.table=tk.Text(root,height=18,width=76,font=('Consolas',13),state='disabled');self.table.pack(padx=16,pady=8)
        tk.Button(root,text='Новая раздача',font=('Arial',12),command=self.deal).pack(pady=8)
        self.players=[];self.layers=[]
        self.print_text('Введите число игроков и имена, затем нажмите «Новая раздача».')
    def print_text(self,s:str)->None:
        self.table.configure(state='normal');self.table.delete('1.0','end');self.table.insert('end',s);self.table.configure(state='disabled')
    def deal(self)->None:
        n=simpledialog.askinteger('Игроки','Число игроков (2–10):',parent=self.root,minvalue=2,maxvalue=10)
        if n is None:return
        names=[]
        for i in range(n):
            name=simpledialog.askstring('Игрок',f'Имя игрока {i+1}:',parent=self.root)
            if not name:return
            names.append(name)
        if 2*n+5>52:messagebox.showerror('Ошибка','Недостаточно карт.');return
        # Каждый игрок перемешивает полную колоду и добавляет секретный слой.
        deck=list(range(52));layers=[]
        for _ in names:
            e,d=make_layer(deck);deck=shuffle([encrypt(c,e) for c in deck]);layers.append(d)
        # Раздача двух карманных карт по кругу плюс пять общих.
        selected=[]
        for _ in range(2):
            for _name in names:selected.append(deck.pop())
        board=[deck.pop() for _ in range(5)]
        def reveal(token:int)->int:
            for d in reversed(layers):token=remove_layer(token,d)
            return token-1
        hands=[[reveal(selected[i*2+j]) for j in range(2)] for i in range(n)]
        community=[reveal(c) for c in board]
        out='Общие карты: '+'  '.join(map(card_name,community))+'\n\n'
        for name,cards in zip(names,hands):out+=f'{name}:  {card_name(cards[0])}  {card_name(cards[1])}\n'
        out+='\nДля учебной демонстрации все руки открыты на одном экране.\nПротокол: секретное перемешивание + слой шифрования каждого участника.'
        self.print_text(out)

def main()->None:
    root=tk.Tk();PokerApp(root);root.mainloop()
if __name__=='__main__':main()
